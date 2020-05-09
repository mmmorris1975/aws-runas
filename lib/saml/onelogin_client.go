package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type oneloginSamlClient struct {
	*BaseAwsClient
	appId           string
	subdomain       string
	mdBaseUrl       string
	apiBaseUrl      string
	apiClientId     string
	apiClientSecret string
	apiToken        *apiToken
}

// NewOneLoginSamlClient creates a OneLogin aware SAML client using authUrl as the authentication endpoint
// OneLogin convention for this is along the lines of __base-url__/trust/saml2/http-post/sso/__id__
// which is the SAML 2.0 Endpoint found under the SSO section for the AWS OneLogin application.
// It's is the same URL which is used to "do the SAML" between OneLogin and AWS
func NewOneLoginSamlClient(authUrl string) (*oneloginSamlClient, error) {
	bsc, err := newBaseAwsClient(authUrl)
	if err != nil {
		return nil, err
	}
	bsc.MfaType = MfaTypeAuto

	c := oneloginSamlClient{BaseAwsClient: bsc}
	c.subdomain = strings.Split(bsc.authUrl.Host, ".")[0]

	if err := c.apiClient(); err != nil {
		return nil, err
	}

	// helps make this testable, real OL urls do the real thing, otherwise use the host provided in the authUrl
	if strings.Contains(c.authUrl.Host, `.onelogin.com`) {
		c.mdBaseUrl = fmt.Sprintf("%s://app.onelogin.com/saml/metadata", c.authUrl.Scheme)
		c.apiBaseUrl = fmt.Sprintf("%s://api.us.onelogin.com", c.authUrl.Scheme) // fixme we may need to deal with regional endpoints (us vs eu vs others)
	} else {
		c.apiBaseUrl = fmt.Sprintf("%s://%s", c.authUrl.Scheme, c.authUrl.Host)
		c.mdBaseUrl = fmt.Sprintf("%s/saml/metadata", c.apiBaseUrl)
	}

	if err = c.parseAppId(); err != nil {
		return nil, err
	}

	// we need this in a few places, so fetch it early
	c.apiToken, err = c.apiAccessToken()
	if err != nil {
		return nil, err
	}

	//c.httpClient.CheckRedirect = nil

	return &c, nil
}

// API credentials for the OneLogin provider are passed in as the 'token' query string parameter in the
// saml_auth_url configuration property.  The value of this parameter is the base64 encoded value of the
// API client ID and API client secret joined with a ':' between them.  On a system like MacOS, or Linux,
// you can use the following command to build that value:
//    echo 'client_id:client_secret' | base64
// with the resulting saml_auth_url property looking like this:
//    https://my-tenant.onelogin.com/trust/saml2/http-post/sso/aws-app-id?token=Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQK
func (c *oneloginSamlClient) apiClient() error {
	t := c.authUrl.Query().Get("token")
	if len(t) < 1 {
		return fmt.Errorf("missing token query parameter")
	}
	// erase any notion of a query string from authUrl, since we only use it internally
	c.authUrl.RawQuery = ""

	b, err := base64.StdEncoding.DecodeString(t)
	if err != nil {
		return err
	}

	s := strings.Split(string(b), `:`)
	if len(s) < 2 {
		return fmt.Errorf("invalid token parameter format")
	}
	c.apiClientId = s[0]
	c.apiClientSecret = s[1]

	return nil
}

func (c *oneloginSamlClient) parseAppId() error {
	s := strings.Split(c.authUrl.Path, "/")
	u := fmt.Sprintf("%s/%s", c.mdBaseUrl, s[len(s)-1])

	res, err := http.Get(u)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("http code %d while fetching metadata", res.StatusCode)
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	re, err := regexp.Compile(`<SingleLogoutService\s+.*?\s+Location="(.*?)"/>`)
	if err != nil {
		return err
	}

	m := re.FindStringSubmatch(fmt.Sprintf("%s", b))
	if m == nil || len(m) < 2 {
		return fmt.Errorf("did not find required data in SAML metadata")
	}

	s = strings.Split(m[1], "/")
	c.appId = s[len(s)-1]

	return nil
}

// Authenticate handles authentication against a OneLogin identity provider
func (c *oneloginSamlClient) Authenticate() error {
	if err := c.gatherCredentials(); err != nil {
		return nil
	}

	return c.auth()
}

// AwsSaml performs a SAML request using the auth URL provided at the start.  The result of this request is cached
// in memory to avoid repeated requests to the OneLogin endpoint.
func (c *oneloginSamlClient) AwsSaml() (string, error) {
	if len(c.rawSamlResponse) > 0 {
		return c.rawSamlResponse, nil
	}

	if err := c.samlRequest(c.authUrl); err != nil {
		return "", err
	}

	return c.rawSamlResponse, nil
}

// attempting to follow the redirect chain to try scraping a form to do the login results in a "must enable JS" page,
// so it seems that we're required to drive through the OneLogin API to handle user authentication.  That means we're
// required to use API token credentials to do authentication.  We're trying to avoid that where at all possible, since
// that means we need to communicate those to everyone looking to configure this provider.
//
// The OneLogin provider allows us to scope these tokens down to just authentication only, so it's "less bad", although
// we still need to find a way to communicate these back to the users
func (c *oneloginSamlClient) auth() error {
	req, err := c.authRequest()
	if err != nil {
		return err
	}

	ar, err := c.doAuthRequest(req)
	if err != nil {
		return err
	}

	if len(ar.StateToken) < 1 {
		c.rawSamlResponse = ar.Data
		return nil
	}

	// MFA required to pass authentication
	return c.handleMfa(ar)
}

func (c *oneloginSamlClient) doAuthRequest(r *http.Request) (*authReply, error) {
	res, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, new(errAuthFailure).WithCode(res.StatusCode).WithText("Error reading response body")
	}

	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusBadRequest || res.StatusCode == http.StatusUnauthorized {
			s := new(authReply)
			if err = json.Unmarshal(data, s); err != nil {
				return nil, new(errAuthFailure).WithCode(res.StatusCode).WithText("Invalid JSON reply")
			}

			return nil, fmt.Errorf(s.Message)
		}

		return nil, new(errAuthFailure).WithCode(res.StatusCode).WithText("Authentication failed")
	}

	ar := new(authReply)
	if err = json.Unmarshal(data, ar); err != nil {
		return nil, err
	}

	return ar, nil
}

func (c *oneloginSamlClient) handleMfa(ar *authReply) error {
	defaultMfa, err := c.defaultMfaDevice(ar.User.Id)
	if err != nil {
		return err
	}

	for _, d := range ar.Devices {
		if d.Id == defaultMfa {
			mfaReq := &verifyMfaRequest{
				AppId:       c.appId,
				DeviceId:    strconv.Itoa(d.Id),
				StateToken:  ar.StateToken,
				DoNotNotify: true,
			}

			u := fmt.Sprintf("%s/api/2/saml_assertion/verify_factor", c.apiBaseUrl)

			if d.Type == "OneLogin Protect" {
				mfaReq.DoNotNotify = false
				return c.handlePushMfa(u, mfaReq)
			}

			// assume all others require prompting for the code
			return c.handleCodeMfa(u, mfaReq)
		}
	}

	return nil
}

func (c *oneloginSamlClient) handlePushMfa(u string, r *verifyMfaRequest) error {
	req, err := c.apiPost(u, r)
	if err != nil {
		return err
	}

	ar, err := c.doAuthRequest(req)
	if err != nil {
		return err
	}

	if strings.Contains(ar.Message, "pending") {
		fmt.Println("Waiting for Push MFA confirmation...")
		time.Sleep(1250 * time.Millisecond)
		r.DoNotNotify = true
		return c.handlePushMfa(u, r)
	} else if strings.EqualFold(ar.Message, "success") {
		c.rawSamlResponse = ar.Data
		return nil
	}

	return fmt.Errorf(ar.Message)
}

func (c *oneloginSamlClient) handleCodeMfa(u string, r *verifyMfaRequest) error {
	if len(c.MfaToken) < 1 {
		if c.MfaTokenProvider != nil {
			t, err := c.MfaTokenProvider()
			if err != nil {
				return err
			}
			c.MfaToken = t
		} else {
			return new(errMfaNotConfigured)
		}
	}
	r.OtpToken = c.MfaToken

	req, err := c.apiPost(u, r)
	if err != nil {
		return err
	}

	ar, err := c.doAuthRequest(req)
	if err != nil {
		if strings.EqualFold(err.Error(), "Failed authentication with this factor") {
			fmt.Println("Invalid MFA Code ... try again")
			c.MfaToken = ""
			return c.handleCodeMfa(u, r)
		}

		return err
	}

	if strings.EqualFold(ar.Message, "success") {
		c.rawSamlResponse = ar.Data
		return nil
	}

	c.MfaToken = ""
	return c.handleCodeMfa(u, r)
}

func (c *oneloginSamlClient) defaultMfaDevice(userId int) (int, error) {
	// fixme OneLogin is moving to a v2 api, however there is no v2 endpoint for this yet
	// I'm assuming this will need to get updated in the future, so I'll leave this little reminder.
	// Despite the path in the url, this endpoint is actually under the MFA section as 'Get Enrolled Factors'
	u := fmt.Sprintf("%s/api/1/users/%d/otp_devices", c.apiBaseUrl, userId)
	req, err := http.NewRequest(http.MethodGet, u, http.NoBody)
	if err != nil {
		return -1, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("bearer:%s", c.apiToken.AccessToken))

	res, err := c.httpClient.Do(req)
	if err != nil {
		return -1, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return -1, fmt.Errorf("http code %d", res.StatusCode)
	}

	or := new(otpReply)
	b, _ := ioutil.ReadAll(res.Body)
	if err = json.Unmarshal(b, or); err != nil {
		return -1, err
	}

	for _, i := range or.Data["otp_devices"] {
		if i.Default {
			return i.Id, nil
		}
	}

	return -1, fmt.Errorf("default MFA device not found")
}

func (c *oneloginSamlClient) authRequest() (*http.Request, error) {
	// Dont' set IPAddress until we find a requirement to do so.  I'm guessing this will involve finding the public IP
	// of our client, which likely means calling out to some Internet endpoint capable of reflecting that back to us
	// whatsmyip.org, icanhazip.com, etc...
	b := authBody{
		Username:  c.Username,
		Password:  c.Password,
		AppId:     c.appId,
		Subdomain: c.subdomain,
	}

	return c.apiPost(fmt.Sprintf("%s/api/2/saml_assertion", c.apiBaseUrl), &b)
}

func (c *oneloginSamlClient) apiPost(u string, body interface{}) (*http.Request, error) {
	var r io.Reader
	r = http.NoBody

	if body != nil {
		j, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(j)
	}

	req, err := http.NewRequest(http.MethodPost, u, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer:%s", c.apiToken.AccessToken))

	return req, nil
}

func (c *oneloginSamlClient) apiAccessToken() (*apiToken, error) {
	u := fmt.Sprintf("%s/auth/oauth2/v2/token", c.apiBaseUrl)
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(`{"grant_type": "client_credentials"}`))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.apiClientId, c.apiClientSecret)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, new(errAuthFailure).WithCode(res.StatusCode).WithText("Failed getting access token")
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	t := new(apiToken)
	if err = json.Unmarshal(b, t); err != nil {
		return nil, err
	}

	return t, nil
}

type apiToken struct {
	AccessToken  string `json:"access_token"`
	AccountId    int    `json:"account_id"`
	CreatedAt    string `json:"created_at"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

type authBody struct {
	Username  string `json:"username_or_email"`
	Password  string `json:"password"`
	AppId     string `json:"app_id"`
	Subdomain string `json:"subdomain"`
	IpAddress string `json:"ip_address,omitempty"`
}

type authReply struct {
	Message     string       `json:"message"`
	Data        string       `json:"data"`
	StateToken  string       `json:"state_token"`
	CallbackUrl string       `json:"callback_url"`
	Devices     []*mfaDevice `json:"devices"`
	User        *user        `json:"user"`
	Status      *replyStatus `json:"status"`
}

type mfaDevice struct {
	Id   int    `json:"device_id"`
	Type string `json:"device_type"`
}

type user struct {
	Id        int    `json:"id"`
	Email     string `json:"email"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Username  string `json:"username"`
}

type verifyMfaRequest struct {
	AppId       string `json:"app_id"`
	DeviceId    string `json:"device_id"`
	StateToken  string `json:"state_token"`
	OtpToken    string `json:"otp_token"`
	DoNotNotify bool   `json:"do_not_notify"`
}

type otpReply struct {
	Status *replyStatus            `json:"status"`
	Data   map[string][]*otpDevice `json:"data"`
}

type replyStatus struct {
	Type    string `json:"type"`
	Code    int    `json:"code"`
	Message string `json:"message"`
	Error   bool   `json:"error"`
}

type otpDevice struct {
	Id           int    `json:"id"`
	Active       bool   `json:"active"`
	Default      bool   `json:"default"`
	NeedsTrigger bool   `json:"needs_trigger"`
	FactorName   string `json:"auth_factor_name"`
	FactorType   string `json:"type_display_name"`
	DisplayName  string `json:"user_display_name"`
}
