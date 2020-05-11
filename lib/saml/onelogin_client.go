package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type oneloginSamlClient struct {
	*BaseAwsClient
	apiToken        *oneloginApiToken
	apiBaseUrl      string
	apiClientId     string
	apiClientSecret string
	appId           string
	subdomain       string
}

// NewOneLoginSamlClient creates a OneLogin aware SAML client using authUrl as the authentication endpoint
// There is a SAML-specific endpoint available, however it requires that you provide the user's credentials with
// every call, and does not persist the user's login state.  We'll take a different tact and use the login page API
// which has a URL in the general form of https://my-tenant.onelogin.com/trust/saml2/launch/__app-id__ where the app-id
// value can be found on the user's application landing page, hovering over the OneLogin AWS Application, and getting
// the last element in the URL path.
func NewOneLoginSamlClient(authUrl string) (*oneloginSamlClient, error) {
	bsc, err := newBaseAwsClient(authUrl)
	if err != nil {
		return nil, err
	}
	bsc.MfaType = MfaTypeAuto

	c := oneloginSamlClient{BaseAwsClient: bsc}
	c.subdomain = strings.Split(bsc.authUrl.Host, ".")[0]

	if err := c.apiClientCredentials(); err != nil {
		return nil, err
	}

	// helps make this testable, real OL urls do the real thing, otherwise use the host provided in the authUrl
	// "secret" region query string param allows callers to set the regional API endpoint, default is "us"
	if strings.Contains(c.authUrl.Host, `.onelogin.com`) {
		region := c.authUrl.Query().Get("region")
		if len(region) < 1 {
			region = "us"
		}
		c.apiBaseUrl = fmt.Sprintf("%s://api.%s.onelogin.com", c.authUrl.Scheme, region)
	} else {
		c.apiBaseUrl = fmt.Sprintf("%s://%s", c.authUrl.Scheme, c.authUrl.Host)
	}

	s := strings.Split(c.authUrl.Path, `/`)
	c.appId = s[len(s)-1]

	// we need this in a few places, so fetch it early
	c.apiToken, err = c.apiAccessToken()
	if err != nil {
		return nil, err
	}

	c.httpClient.CheckRedirect = nil
	return &c, nil
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

func (c *oneloginSamlClient) auth() error {
	creds := map[string]string{
		"username_or_email": c.Username,
		"password":          c.Password,
		"subdomain":         c.subdomain,
	}

	req, err := c.apiPostReq(fmt.Sprintf("%s/api/1/login/auth", c.apiBaseUrl), &creds)
	if err != nil {
		return err
	}

	ar, err := c.doAuthRequest(req)
	if err != nil {
		return err
	}
	token := ar.Data[0].SessionToken

	if len(ar.Data) > 0 && len(ar.Data[0].MfaDevices) > 0 {
		token, err = c.handleMfa(ar.Data[0])
		if err != nil {
			return err
		}
	}

	if err = c.exchangeToken(token); err != nil {
		return err
	}

	return nil
}

// API credentials for the OneLogin provider are passed in as the 'token' query string parameter in the
// saml_auth_url configuration property.  The value of this parameter is the base64 encoded value of the
// API client ID and API client secret joined with a ':' between them.  On a system like MacOS, or Linux,
// you can use the following command to build that value:
//    echo 'client_id:client_secret' | base64
// with the resulting saml_auth_url property looking like this:
//    https://my-tenant.onelogin.com/trust/saml2/launch/app-id?token=Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQK
func (c *oneloginSamlClient) apiClientCredentials() error {
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

func (c *oneloginSamlClient) apiAccessToken() (*oneloginApiToken, error) {
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

	t := new(oneloginApiToken)
	if err = json.Unmarshal(b, t); err != nil {
		return nil, err
	}

	return t, nil
}

func (c *oneloginSamlClient) apiPostReq(u string, body interface{}) (*http.Request, error) {
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

func (c *oneloginSamlClient) doAuthRequest(r *http.Request) (*oneloginAuthReplyV1, error) {
	res, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, new(errAuthFailure).WithCode(res.StatusCode).WithText("Error reading response body")
	}

	ar := new(oneloginAuthReplyV1)
	if err = json.Unmarshal(data, ar); err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, new(errAuthFailure).WithCode(res.StatusCode).WithText(ar.Status.Message)
	}

	return ar, nil
}

func (c *oneloginSamlClient) handleMfa(data *oneloginAuthDataV1) (string, error) {
	defaultMfaId, err := c.defaultMfaDevice(data.User.Id)
	if err != nil {
		return "", err
	}

	for _, d := range data.MfaDevices {
		if d.Id == defaultMfaId {
			mfaReq := &oneloginVerifyFactorRequest{
				DeviceId:    strconv.Itoa(d.Id),
				StateToken:  data.StateToken,
				DoNotNotify: true,
			}

			if d.Type == "OneLogin Protect" {
				mfaReq.DoNotNotify = false
				return c.handlePushMfa(data.CallbackUrl, mfaReq)
			}

			// assume all others require prompting for the code
			return c.handleCodeMfa(data.CallbackUrl, mfaReq)
		}
	}

	return "", new(errMfaNotConfigured)
}

func (c *oneloginSamlClient) defaultMfaDevice(userId int) (int, error) {
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
		return -1, new(errMfaFailure).WithCode(res.StatusCode)
	}

	or := new(oneloginEnrolledFactorsV1)
	b, _ := ioutil.ReadAll(res.Body)
	if err = json.Unmarshal(b, or); err != nil {
		return -1, err
	}

	for _, i := range or.Data["otp_devices"] {
		if i.Default && i.Active {
			return i.Id, nil
		}
	}

	return -1, fmt.Errorf("default MFA device not found")
}

func (c *oneloginSamlClient) handlePushMfa(url string, req *oneloginVerifyFactorRequest) (string, error) {
	r, err := c.apiPostReq(url, req)
	if err != nil {
		return "", err
	}

	ar, err := c.doAuthRequest(r)
	if err != nil {
		return "", err
	}

	if strings.Contains(ar.Status.Message, "pending") {
		fmt.Println("Waiting for Push MFA confirmation...")
		time.Sleep(1250 * time.Millisecond)
		req.DoNotNotify = true
		return c.handlePushMfa(url, req)
	} else if strings.EqualFold(ar.Status.Message, "success") {
		if len(ar.Data) > 0 && len(ar.Data[0].SessionToken) > 0 {
			return ar.Data[0].SessionToken, nil
		}
	}

	return "", new(errMfaFailure).WithCode(ar.Status.Code)
}

func (c *oneloginSamlClient) handleCodeMfa(url string, req *oneloginVerifyFactorRequest) (string, error) {
	if len(c.MfaToken) < 1 {
		if c.MfaTokenProvider != nil {
			t, err := c.MfaTokenProvider()
			if err != nil {
				return "", err
			}
			c.MfaToken = t
		} else {
			return "", new(errMfaNotConfigured)
		}
	}
	req.OtpToken = c.MfaToken

	r, err := c.apiPostReq(url, req)
	if err != nil {
		return "", err
	}

	ar, err := c.doAuthRequest(r)
	if err != nil {
		if strings.Contains(err.Error(), "Failed authentication with this factor") {
			fmt.Println("Invalid MFA Code ... try again")
			c.MfaToken = ""
			return c.handleCodeMfa(url, req)
		}

		return "", new(errMfaFailure)
	}

	if strings.EqualFold(ar.Status.Message, "success") {
		if len(ar.Data) > 0 && len(ar.Data[0].SessionToken) > 0 {
			return ar.Data[0].SessionToken, nil
		}
	}

	c.MfaToken = ""
	return c.handleCodeMfa(url, req)
}

// If successful this wil provide the cookie to persist the user's login state, which we can use across
// aws-runas invocations to minimize the number of time the user has to authentication to OneLogin
func (c *oneloginSamlClient) exchangeToken(st string) error {
	u := fmt.Sprintf("%s://%s/session_via_api_token", c.authUrl.Scheme, c.authUrl.Host)
	body := url.Values{}
	body.Set("session_token", st)

	res, err := c.httpClient.Post(u, "application/x-www-form-urlencoded", strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		return new(errAuthFailure).WithCode(res.StatusCode).WithText("Session Token Exchange Failed")
	}

	return nil
}

type oneloginApiToken struct {
	AccessToken string `json:"access_token"`
	AccountId   int    `json:"account_id"`
	CreatedAt   string `json:"created_at"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type oneloginAuthReplyV1 struct {
	Status *oneloginApiStatus    `json:"status"`
	Data   []*oneloginAuthDataV1 `json:"data"`
}

type oneloginApiStatus struct {
	Code    int    `json:"code"`
	Error   bool   `json:"error"`
	Message string `json:"message"`
	Type    string `json:"type"`
}

type oneloginAuthDataV1 struct {
	CallbackUrl  string               `json:"callback_url"`
	ExpiresAt    string               `json:"expires_at"`
	MfaDevices   []*oneloginMfaDevice `json:"devices"`
	ReturnUrl    string               `json:"return_to_url"`
	SessionToken string               `json:"session_token"`
	StateToken   string               `json:"state_token"`
	Status       string               `json:"status"`
	User         *oneloginUser        `json:"user"`
}

type oneloginMfaDevice struct {
	Id   int    `json:"device_id"`
	Type string `json:"device_type"`
}

type oneloginUser struct {
	Id        int    `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Username  string `json:"username"`
}

type oneloginEnrolledFactorsV1 struct {
	Status *oneloginApiStatus                    `json:"status"`
	Data   map[string][]*oneloginEnrolledFactors `json:"data"`
}

type oneloginVerifyFactorRequest struct {
	DeviceId    string `json:"device_id"`
	DoNotNotify bool   `json:"do_not_notify"`
	OtpToken    string `json:"otp_token"`
	StateToken  string `json:"state_token"`
}

type oneloginEnrolledFactors struct {
	Id           int    `json:"id"`
	Type         string `json:"auth_factor_name"`
	Active       bool   `json:"active"`
	Default      bool   `json:"default"`
	NeedsTrigger bool   `json:"needs_trigger"`
	DisplayName  string `json:"type_display_name"`
}
