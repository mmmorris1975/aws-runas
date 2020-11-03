package external

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const oneloginIdentityProvider = "OneloginIdentityProvider"

type oneloginClient struct {
	*baseClient
	apiBaseUrl string
	apiToken   *oneloginApiToken
	subdomain  string
}

// NewOneloginClient returns a new AuthenticationClient capable of handling SAML and WebIdentity operations
// using the OneLogin identity platform
func NewOneloginClient(url string) (*oneloginClient, error) {
	bc, err := newBaseClient(url)
	if err != nil {
		return nil, err
	}

	oc := new(oneloginClient)
	oc.baseClient = bc
	oc.subdomain = strings.Split(bc.authUrl.Host, `.`)[0]
	oc.setApiBaseUrl()

	if err := oc.apiAccessToken(); err != nil {
		return nil, err
	}

	// wipe out any query string data as it's not needed past this point
	oc.authUrl.RawQuery = ""
	return oc, nil
}

// Authenticate performs authentication against OneLogin.  This delegates to AuthenticateWithContext using
// context.Background()
func (c *oneloginClient) Authenticate() error {
	return c.AuthenticateWithContext(context.Background())
}

// AuthenticateWithContext performs authentication against OneLogin using the specified Context, which is passed
// along to the underlying HTTP requests.  If necessary, it will prompt for the authentication credentials.
func (c *oneloginClient) AuthenticateWithContext(ctx context.Context) error {
	if err := c.gatherCredentials(); err != nil {
		return err
	}

	return c.auth(ctx)
}

// Identity returns the identity information for the user
func (c *oneloginClient) Identity() (*identity.Identity, error) {
	return c.identity(oneloginIdentityProvider), nil
}

// IdentityToken calls IdentityTokenWithContext with a background context.
func (c *oneloginClient) IdentityToken() (*credentials.OidcIdentityToken, error) {
	return c.IdentityTokenWithContext(context.Background())
}

// IdentityTokenWithContext retrieves the OIDC Identity Token from OneLogin.  The Authenticate() (or AuthenticateWithContext())
// methods must be called before using this method, otherwise an error will be returned.
func (c *oneloginClient) IdentityTokenWithContext(ctx context.Context) (*credentials.OidcIdentityToken, error) {
	pkce, err := newPkceCode()
	if err != nil {
		return nil, err
	}
	authzQS := c.pkceAuthzRequest(pkce.Challenge())

	vals, err := c.oauthAuthorize(fmt.Sprintf("%s/auth", c.authUrl.String()), authzQS, true)
	if err != nil {
		if err = c.AuthenticateWithContext(ctx); err != nil {
			return nil, err
		}
		return c.IdentityTokenWithContext(ctx)
	}

	if vals.Get("state") != authzQS.Get("state") {
		return nil, errOauthStateMismatch
	}

	token, err := c.oauthToken(fmt.Sprintf("%s/token", c.authUrl.String()), vals.Get("code"), pkce.Verifier())
	if err != nil {
		return nil, err
	}

	return token.IdToken, nil
}

// SamlAssertion calls SamlAssertionWithContext using a background context
func (c *oneloginClient) SamlAssertion() (*credentials.SamlAssertion, error) {
	return c.SamlAssertionWithContext(context.Background())
}

// SamlAssertionWithContext retrieves the SAML Assertion from OneLogin.
// Authentication will automatically be attempted, if required
func (c *oneloginClient) SamlAssertionWithContext(ctx context.Context) (*credentials.SamlAssertion, error) {
	if err := c.samlRequest(ctx, c.authUrl); err != nil {
		return nil, err
	}

	if c.saml == nil || len(*c.saml) < 1 {
		if err := c.AuthenticateWithContext(ctx); err != nil {
			return nil, err
		}
		return c.SamlAssertionWithContext(ctx)
	}

	return c.saml, nil
}

// helps make this testable, real OL urls do the real thing, otherwise use the host provided in the authUrl.
// A "secret" region query string param allows callers to set the regional API endpoint, default is "us"
func (c *oneloginClient) setApiBaseUrl() {
	defer c.authUrl.Query().Del("region")

	if strings.Contains(strings.ToLower(c.authUrl.Host), `.onelogin.com`) {
		region := `us`
		regionQs := c.authUrl.Query().Get("region")
		if len(regionQs) > 0 {
			region = regionQs
		}
		c.apiBaseUrl = fmt.Sprintf("%s://api.%s.onelogin.com", c.authUrl.Scheme, region)
	} else {
		c.apiBaseUrl = fmt.Sprintf("%s://%s", c.authUrl.Scheme, c.authUrl.Host)
	}
}

func (c *oneloginClient) apiAccessToken() error {
	id, secret, err := c.apiClientCredentials()
	if err != nil {
		return err
	}

	u := fmt.Sprintf("%s/auth/oauth2/v2/token", c.apiBaseUrl)
	body := strings.NewReader(`{"grant_type": "client_credentials"}`)

	req, err := http.NewRequest(http.MethodPost, u, body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(id, secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	data, err := c.sendApiRequest(req)
	if err != nil {
		return err
	}

	t := new(oneloginApiToken)
	if err := json.Unmarshal(data, t); err != nil {
		return err
	}
	c.apiToken = t

	return nil
}

func (c *oneloginClient) apiClientCredentials() (string, string, error) {
	defer c.authUrl.Query().Del("token")

	t := c.authUrl.Query().Get("token")
	if len(t) < 1 {
		return "", "", errors.New("missing token query parameter")
	}

	b, err := base64.StdEncoding.DecodeString(t)
	if err != nil {
		return "", "", err
	}

	s := strings.Split(string(b), `:`)
	if len(s) < 2 {
		return "", "", errors.New("invalid token parameter format")
	}

	return s[0], s[1], nil
}

func (c *oneloginClient) auth(ctx context.Context) error {
	creds := map[string]string{
		"username_or_email": c.Username,
		"password":          c.Password,
		"subdomain":         c.subdomain,
	}

	req, err := c.apiPostReq(ctx, fmt.Sprintf("%s/api/1/login/auth", c.apiBaseUrl), &creds)
	if err != nil {
		return err
	}

	data, err := c.sendApiRequest(req)
	if err != nil {
		return err
	}

	authReply := new(oneloginAuthReply)
	if err := json.Unmarshal(data, authReply); err != nil {
		return err
	}
	sessionToken := authReply.Data[0].SessionToken

	if len(authReply.Data[0].Devices) > 0 {
		sessionToken, err = c.handleMfa(ctx, authReply.Data[0])
		if err != nil {
			return err
		}
	}

	return c.exchangeToken(sessionToken)
}

func (c *oneloginClient) handleMfa(ctx context.Context, data *oneloginAuthData) (string, error) {
	factors, err := c.activeMfaFactors(data.User.Id)
	if err != nil {
		return "", err
	}

	mfaReq := &oneloginVerifyFactorRequest{
		StateToken:  data.StateToken,
		DoNotNotify: true,
	}

	switch c.MfaType {
	case MfaTypeNone:
		// fall through
	case MfaTypeCode:
		for _, d := range factors {
			// only Google Authenticator supported at this time
			if d.Type == "Google Authenticator" {
				mfaReq.DeviceId = strconv.Itoa(d.Id)
				return c.handleCodeMfa(ctx, data.CallbackUrl, mfaReq)
			}
		}
	case MfaTypePush:
		for _, d := range factors {
			if d.Type == "OneLogin Protect" && d.NeedsTrigger {
				mfaReq.DeviceId = strconv.Itoa(d.Id)
				mfaReq.DoNotNotify = false
				return c.handlePushMfa(ctx, data.CallbackUrl, mfaReq)
			}
		}
	default:
		for _, d := range factors {
			if d.Default {
				mfaReq.DeviceId = strconv.Itoa(d.Id)

				if d.Type == "OneLogin Protect" {
					mfaReq.DoNotNotify = false
					return c.handlePushMfa(ctx, data.CallbackUrl, mfaReq)
				}

				// assume all others require prompting for the code
				return c.handleCodeMfa(ctx, data.CallbackUrl, mfaReq)
			}
		}
	}

	return "", errMfaNotConfigured
}

func (c *oneloginClient) activeMfaFactors(userId int) ([]*oneloginMfaFactor, error) {
	u := fmt.Sprintf("%s/api/1/users/%d/otp_devices", c.apiBaseUrl, userId)
	req, err := http.NewRequest(http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("bearer:%s", c.apiToken.AccessToken))

	data, err := c.sendApiRequest(req)
	if err != nil {
		return nil, err
	}

	or := new(oneloginEnrolledFactors)
	if err = json.Unmarshal(data, or); err != nil {
		return nil, err
	}

	factors := make([]*oneloginMfaFactor, 0)
	for _, i := range or.Data["otp_devices"] {
		if i.Active {
			factors = append(factors, i)
		}
	}

	if len(factors) > 0 {
		return factors, nil
	}

	return nil, errors.New("no active MFA factors found")
}

func (c *oneloginClient) handlePushMfa(ctx context.Context, url string, req *oneloginVerifyFactorRequest) (string, error) {
	r, err := c.apiPostReq(ctx, url, req)
	if err != nil {
		return "", err
	}

	data, err := c.sendApiRequest(r)
	if err != nil {
		return "", err
	}

	ar := new(oneloginAuthReply)
	if err := json.Unmarshal(data, ar); err != nil {
		return "", err
	}

	if strings.Contains(ar.Status.Message, "pending") {
		fmt.Println("Waiting for Push MFA confirmation...")
		time.Sleep(1250 * time.Millisecond)
		req.DoNotNotify = true
		return c.handlePushMfa(ctx, url, req)
	} else if strings.EqualFold(ar.Status.Message, "success") {
		if len(ar.Data) > 0 && len(ar.Data[0].SessionToken) > 0 {
			return ar.Data[0].SessionToken, nil
		}
	}

	return "", &oneloginApiError{Status: ar.Status}
}

func (c *oneloginClient) handleCodeMfa(ctx context.Context, url string, req *oneloginVerifyFactorRequest) (string, error) {
	if len(c.MfaTokenCode) < 1 {
		if c.MfaTokenProvider != nil {
			t, err := c.MfaTokenProvider()
			if err != nil {
				return "", err
			}
			c.MfaTokenCode = t
		} else {
			return "", errMfaNotConfigured
		}
	}
	req.OtpToken = c.MfaTokenCode

	r, err := c.apiPostReq(ctx, url, req)
	if err != nil {
		return "", err
	}

	body, err := c.sendApiRequest(r)
	if err != nil {
		if strings.Contains(err.Error(), "Failed authentication with this factor") {
			fmt.Println("Invalid MFA Code ... try again")
			c.MfaTokenCode = ""
			return c.handleCodeMfa(ctx, url, req)
		}

		return "", err
	}

	ar := new(oneloginAuthReply)
	if err := json.Unmarshal(body, ar); err != nil {
		return "", err
	}

	if strings.EqualFold(ar.Status.Message, "success") {
		if len(ar.Data) > 0 && len(ar.Data[0].SessionToken) > 0 {
			return ar.Data[0].SessionToken, nil
		}
	}

	c.MfaTokenCode = ""
	return c.handleCodeMfa(ctx, url, req)
}

func (c *oneloginClient) exchangeToken(st string) error {
	u := fmt.Sprintf("%s://%s/session_via_api_token", c.authUrl.Scheme, c.authUrl.Host)
	body := url.Values{}
	body.Set("session_token", st)

	res, err := c.httpClient.Post(u, "application/x-www-form-urlencoded", strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		return &oneloginApiError{
			Status: &oneloginApiStatus{
				Error:   true,
				Code:    res.StatusCode,
				Type:    res.Status,
				Message: "Session Token Exchange Failed",
			},
		}
	}

	return nil
}

func (c *oneloginClient) apiPostReq(ctx context.Context, u string, body interface{}) (*http.Request, error) {
	var r io.Reader = http.NoBody

	if body != nil {
		j, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(j)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer:%s", c.apiToken.AccessToken))

	return req, nil
}

func (c *oneloginClient) sendApiRequest(req *http.Request) ([]byte, error) {
	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	b, err := ioutil.ReadAll(io.LimitReader(res.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		r := new(oneloginApiError)
		_ = json.Unmarshal(b, r)
		return nil, r
	}

	return b, nil
}

type oneloginApiToken struct {
	AccessToken string `json:"access_token"`
	AccountId   int    `json:"account_id"`
	CreatedAt   string `json:"created_at"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type oneloginAuthReply struct {
	Status *oneloginApiStatus  `json:"status"`
	Data   []*oneloginAuthData `json:"data"`
}

type oneloginApiStatus struct {
	Error   bool   `json:"error"`
	Code    int    `json:"code"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

type oneloginAuthData struct {
	Status       string               `json:"status"`
	SessionToken string               `json:"session_token"`
	StateToken   string               `json:"state_token"`
	CallbackUrl  string               `json:"callback_url"`
	Devices      []*oneloginMfaDevice `json:"devices"`
	User         *oneloginUser        `json:"user"`
}

type oneloginMfaDevice struct {
	DeviceType string `json:"device_type"`
	DeviceId   int    `json:"device_id"`
}

type oneloginUser struct {
	Id        int    `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Username  string `json:"username"`
}

type oneloginEnrolledFactors struct {
	Status *oneloginApiStatus              `json:"status"`
	Data   map[string][]*oneloginMfaFactor `json:"data"`
}

type oneloginMfaFactor struct {
	Id           int    `json:"id"`
	Type         string `json:"auth_factor_name"`
	Active       bool   `json:"active"`
	Default      bool   `json:"default"`
	NeedsTrigger bool   `json:"needs_trigger"`
	DisplayName  string `json:"type_display_name"`
}

type oneloginVerifyFactorRequest struct {
	DeviceId    string `json:"device_id"`
	DoNotNotify bool   `json:"do_not_notify"`
	OtpToken    string `json:"otp_token"`
	StateToken  string `json:"state_token"`
}

type oneloginApiError struct {
	Status *oneloginApiStatus `json:"status"`
}

func (e *oneloginApiError) Error() string {
	return e.Status.Message
}
