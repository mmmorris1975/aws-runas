package saml

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

type oneloginSamlClient struct {
	*BaseAwsClient
	appId           string
	subdomain       string
	apiClientId     string
	apiClientSecret string
}

// NewOneLoginSamlClient creates a OneLogin aware SAML client using authUrl as the authentication endpoint
// OneLogin convention for this is along the lines of __base-url__/trust/saml2/http-post/sso/__id__
// This is the same URL which is used to "do the SAML" between OneLogin and AWS
func NewOneLoginSamlClient(authUrl string) (*oneloginSamlClient, error) {
	bsc, err := newBaseAwsClient(authUrl)
	if err != nil {
		return nil, err
	}
	bsc.MfaType = MfaTypeAuto

	c := oneloginSamlClient{BaseAwsClient: bsc}
	c.subdomain = strings.Split(bsc.authUrl.Host, ".")[0]

	if err := c.parseAppId(); err != nil {
		return nil, err
	}

	return &c, nil
}

func (c *oneloginSamlClient) parseAppId() error {
	s := strings.Split(c.authUrl.Path, "/")
	u := fmt.Sprintf("https://app.onelogin.com/saml/metadata/%s", s[len(s)-1])

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

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return new(errAuthFailure).WithCode(res.StatusCode)
	}

	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusBadRequest || res.StatusCode == http.StatusUnauthorized {
			fmt.Printf("%s\n", data)
			s := new(authStatus)
			if err = json.Unmarshal(data, s); err != nil {
				return new(errAuthFailure).WithCode(res.StatusCode)
			}

			return fmt.Errorf(s.Message)
		}

		return new(errAuthFailure).WithCode(res.StatusCode)
	}

	ar := new(authReply)
	if err := json.Unmarshal(data, ar); err != nil {
		return err
	}

	if ar.Status.Code == http.StatusOK {
		if strings.EqualFold("success", ar.Status.Message) {
			c.rawSamlResponse = ar.Data
			return nil
		} else {
			// todo this should be some kind of MFA handling requirement
		}
	}

	return nil
}

func (c *oneloginSamlClient) authRequest() (*http.Request, error) {
	t, err := c.apiAccessToken()
	if err != nil {
		return nil, err
	}

	// Dont' set IPAddress until we find a requirement to do so.  I'm guessing this will involve finding the public IP
	// of our client, which likely means calling out to some Internet endpoint capable of reflecting that back to us
	// whatsmyip.org, icanhazip.com, etc...
	b := authBody{
		Username:  c.Username,
		Password:  c.Password,
		AppId:     c.appId,
		Subdomain: c.subdomain,
	}

	j, err := json.Marshal(&b)
	if err != nil {
		return nil, err
	}

	u := "https://api.us.onelogin.com/api/1/saml_assertion" // fixme we may need to deal with regional endpoints (us vs eu vs others)
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(j))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer:%s", t.AccessToken))

	return req, nil
}

func (c *oneloginSamlClient) apiAccessToken() (*authToken, error) {
	u := "https://api.us.onelogin.com/auth/oauth2/v2/token" // fixme we may need to deal with regional endpoints (us vs eu vs others)
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
		return nil, new(errAuthFailure).WithCode(res.StatusCode)
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	t := new(authToken)
	if err = json.Unmarshal(b, t); err != nil {
		return nil, err
	}

	return t, nil
}

type authToken struct {
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
	//IpAddress string `json:"ip_address,omitempty"`
}

type authStatus struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Error   bool   `json:"error"`
	Code    int    `json:"code"`
}

type authReply struct {
	Status *authStatus `json:"status"`
	Data   string      `json:"data"`
}
