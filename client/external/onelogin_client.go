/*
 * Copyright (c) 2021 Michael Morris. All Rights Reserved.
 *
 * Licensed under the MIT license (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * https://github.com/mmmorris1975/aws-runas/blob/master/LICENSE
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under the License.
 */

package external

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
)

const oneloginIdentityProvider = "OneloginIdentityProvider"

type oneloginClient struct {
	*baseClient
	apiBaseUrl string
	apiToken   *oneloginApiToken
	subdomain  string
	appId      string
}

// NewOneloginClient returns a new AuthenticationClient capable of handling SAML and WebIdentity operations
// using the OneLogin identity platform.
func NewOneloginClient(url string) (*oneloginClient, error) {
	bc, err := newBaseClient(url)
	if err != nil {
		return nil, err
	}

	oc := new(oneloginClient)
	oc.baseClient = bc
	oc.subdomain = strings.Split(bc.authUrl.Host, `.`)[0]
	oc.appId = oc.authUrl.Query().Get("app_id")
	oc.setApiBaseUrl()

	if err := oc.apiAccessToken(); err != nil {
		return nil, err
	}

	// wipe out any query string data as it's not needed past this point
	oc.authUrl.RawQuery = ""
	return oc, nil
}

// Authenticate performs authentication against OneLogin.  This delegates to AuthenticateWithContext using
// context.Background().
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

// Identity returns the identity information for the user.
func (c *oneloginClient) Identity() (*identity.Identity, error) {
	return c.identity(oneloginIdentityProvider), nil
}

// Roles retrieves the available roles for the user.  Attempting to call this method
// against an Oauth/OIDC client will return an error.
func (c *oneloginClient) Roles(...string) (*identity.Roles, error) {
	if c.saml == nil || len(*c.saml) < 1 {
		var err error
		c.saml, err = c.SamlAssertion()
		if err != nil {
			return nil, err
		}
	}

	return c.roles()
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

// SamlAssertion calls SamlAssertionWithContext using a background context.
func (c *oneloginClient) SamlAssertion() (*credentials.SamlAssertion, error) {
	return c.SamlAssertionWithContext(context.Background())
}

// SamlAssertionWithContext retrieves the SAML Assertion from OneLogin.
// Authentication will automatically be attempted, if required.
// There are 2 ways to go about this with OneLogin:
//  1. calling the saml_assertion API endpoint.
//     - This will authenticate the user with the API request (username/password are required request params)
//     - It appears that MFA at a user auth, or app policy level is handled with this method
//     - This also requires knowledge of the App Id value, which is only visible in the admin console (not the app URL
//     in the user's OL portal).  However, since we already need the Client ID and secret from the admin to make this
//     client work, it should be a simple "all in one" ask for the Client ID and Secret for the API auth + the App ID
//  2. authenticate the user via AuthenticateWithContext() then request the app URL as seen in the user's OL portal
//     - No knowledge of the App Id value required, but we still need an admin to provide Client ID/secret (the `token`
//     query param in the AWS config URL) in order to make the client work
//
// Option 1 would be the most "OneLogin" way of doing this and is probably the more correct implementation.
func (c *oneloginClient) SamlAssertionWithContext(ctx context.Context) (*credentials.SamlAssertion, error) {
	if c.appId == "" {
		return nil, &oneloginApiErrorV2{Status: -1, Message: "missing app_id query parameter"}
	}

	if c.Username == "" || c.Password == "" {
		if err := c.gatherCredentials(); err != nil {
			return nil, err
		}
	}

	u := fmt.Sprintf("%s/api/2/saml_assertion", c.apiBaseUrl)

	body := map[string]string{
		"username_or_email": c.Username,
		"password":          c.Password,
		"subdomain":         c.subdomain,
		"app_id":            c.appId,
	}

	req, err := c.apiPostReq(ctx, u, &body)
	if err != nil {
		return nil, err
	}

	data, err := c.sendApiV2Request(req)
	if err != nil {
		return nil, err
	}

	t := new(oneloginSamlReply)
	if err = json.Unmarshal(data, t); err != nil {
		return nil, err
	}

	if len(t.Data) > 0 {
		c.saml = (*credentials.SamlAssertion)(&t.Data)
	} else if len(t.Devices) > 0 {
		verifier := samlV2MfaVerifier
		verifier.send = c.sendApiV2Request

		var saml string
		saml, err = c.handleMfa(ctx, &t.oneloginAuthData, verifier)
		if err != nil {
			return nil, err
		}
		c.saml = (*credentials.SamlAssertion)(&saml)
	}

	if c.saml == nil || len(*c.saml) < 1 {
		return nil, errors.New("failed to obtain SAML assertion")
	}
	return c.saml, nil
}

// helps make this testable, real OL urls do the real thing, otherwise use the host provided in the authUrl.
// A "secret" region query string param allows callers to set the regional API endpoint, default is "us".
func (c *oneloginClient) setApiBaseUrl() {
	defer c.authUrl.Query().Del("region") //nolint:staticcheck

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

	// ref: https://developers.onelogin.com/api-docs/2/oauth20-tokens/generate-tokens-2
	u := fmt.Sprintf("%s/auth/oauth2/v2/token", c.apiBaseUrl)
	body := strings.NewReader(`{"grant_type": "client_credentials"}`)

	var req *http.Request
	req, err = http.NewRequestWithContext(context.Background(), http.MethodPost, u, body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(id, secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	var data []byte
	data, err = c.sendApiRequest(req)
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
	defer c.authUrl.Query().Del("token") //nolint:staticcheck

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

	// ref: https://developers.onelogin.com/api-docs/1/login-page/create-session-login-token
	req, err := c.apiPostReq(ctx, fmt.Sprintf("%s/api/1/login/auth", c.apiBaseUrl), &creds)
	if err != nil {
		return err
	}

	var data []byte
	data, err = c.sendApiRequest(req)
	if err != nil {
		return err
	}

	authReply := new(oneloginAuthReply)
	if err = json.Unmarshal(data, authReply); err != nil {
		return err
	}

	if len(authReply.Data) == 0 || authReply.Data[0] == nil {
		return errors.New("invalid authentication response received")
	}
	sessionToken := authReply.Data[0].SessionToken

	if len(authReply.Data[0].Devices) > 0 {
		verifier := authV1MfaVerifier
		verifier.send = c.sendApiRequest

		sessionToken, err = c.handleMfa(ctx, authReply.Data[0], verifier)
		if err != nil {
			return err
		}
	}

	return c.exchangeToken(sessionToken)
}

//nolint:gocognit // won't simplify
func (c *oneloginClient) handleMfa(ctx context.Context, data *oneloginAuthData, verifier mfaVerifier) (string, error) {
	if data == nil || data.User == nil {
		return "", errors.New("invalid MFA response received")
	}

	factors, err := c.activeMfaFactors(ctx, data.User.Id)
	if err != nil {
		return "", err
	}

	mfaReq := &oneloginVerifyFactorRequest{
		AppId:       c.appId,
		StateToken:  data.StateToken,
		DoNotNotify: true,
	}

	var u *url.URL
	u, err = url.Parse(data.CallbackUrl)
	if err != nil {
		return "", err
	}

	data.CallbackUrl = c.apiBaseUrl + u.RequestURI()

	switch c.MfaType {
	case MfaTypeNone:
		// fall through
	case MfaTypeCode:
		for _, d := range factors {
			if slices.Contains([]string{"OneLogin", "Google Authenticator", "SMS", "OneLogin Email"}, d.Type) {
				return c.handleCodeMfa(ctx, data.CallbackUrl, mfaReq, d, verifier)
			}
		}
	case MfaTypePush:
		for _, d := range factors {
			if slices.Contains([]string{"OneLogin", "OneLogin Voice"}, d.Type) {
				mfaReq.DoNotNotify = false
				return c.handlePushMfa(ctx, data.CallbackUrl, mfaReq, d, verifier)
			}
		}
	default:
		for _, d := range factors {
			if d.Default {
				if slices.Contains([]string{"OneLogin", "OneLogin Voice"}, d.Type) {
					mfaReq.DoNotNotify = false
					return c.handlePushMfa(ctx, data.CallbackUrl, mfaReq, d, verifier)
				}

				// assume all others require prompting for the code
				return c.handleCodeMfa(ctx, data.CallbackUrl, mfaReq, d, verifier)
			}
		}
	}

	return "", errMfaNotConfigured
}

func (c *oneloginClient) activeMfaFactors(ctx context.Context, userId int) ([]*oneloginMfaFactor, error) {
	// ref: https://developers.onelogin.com/api-docs/2/multi-factor-authentication/enrolled-factors
	//    Will want to also look at this: https://developers.onelogin.com/api-docs/2/multi-factor-authentication/MFAv2
	u := fmt.Sprintf("%s/api/2/mfa/users/%d/devices", c.apiBaseUrl, userId)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("%s %s", c.apiToken.TokenType, c.apiToken.AccessToken))

	var data []byte
	data, err = c.sendApiV2Request(req)
	if err != nil {
		return nil, err
	}

	factors := make([]*oneloginMfaFactor, 0)
	if err = json.Unmarshal(data, &factors); err != nil {
		return nil, err
	}

	if len(factors) > 0 {
		return factors, nil
	}

	return nil, errors.New("no active MFA factors found")
}

func (c *oneloginClient) handlePushMfa(ctx context.Context, url string, req *oneloginVerifyFactorRequest, factor *oneloginMfaFactor, verifier mfaVerifier) (string, error) {
	req.DeviceId = factor.Id

	r, err := c.apiPostReq(ctx, url, req)
	if err != nil {
		return "", err
	}

	body, err := verifier.send(r)
	if err != nil {
		return "", err
	}

	result, err := verifier.parse(body)
	if err != nil {
		return "", err
	}

	if result.token != "" {
		return result.token, nil
	}

	if result.pending {
		fmt.Println("Waiting for Push MFA confirmation...")
		time.Sleep(1250 * time.Millisecond)
		req.DoNotNotify = true
		return c.handlePushMfa(ctx, url, req, factor, verifier)
	}

	return "", errors.New("unexpected push MFA response")
}

func (c *oneloginClient) handleCodeMfa(ctx context.Context, url string, req *oneloginVerifyFactorRequest, factor *oneloginMfaFactor, verifier mfaVerifier) (string, error) {
	req.DeviceId = factor.Id

	if len(c.MfaTokenCode) < 1 {
		if c.MfaTokenProvider == nil {
			return "", errMfaNotConfigured
		}

		c.mfaFactorName = factor.DisplayName
		code, err := c.MfaTokenProvider()
		if err != nil {
			return "", err
		}
		c.MfaTokenCode = code
	}
	req.OtpToken = c.MfaTokenCode

	r, err := c.apiPostReq(ctx, url, req)
	if err != nil {
		return "", err
	}

	body, err := verifier.send(r)
	if err != nil {
		if verifier.isInvalidAttempt(err) {
			fmt.Println("Invalid MFA Code ... try again")
			c.MfaTokenCode = ""
			return c.handleCodeMfa(ctx, url, req, factor, verifier)
		}

		return "", err
	}

	result, err := verifier.parse(body)
	if err != nil {
		return "", err
	}

	if result.token != "" {
		return result.token, nil
	}

	if result.pending {
		c.MfaTokenCode = ""
		return c.handleCodeMfa(ctx, url, req, factor, verifier)
	}

	return "", errors.New("unexpected code MFA response")
}

func (c *oneloginClient) exchangeToken(st string) error {
	// ref: https://developers.onelogin.com/api-docs/1/login-page/create-session-via-token
	u := fmt.Sprintf("%s://%s/session_via_api_token", c.authUrl.Scheme, c.authUrl.Host)
	body := url.Values{}
	body.Set("session_token", st)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, u, strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var res *http.Response
	res, err = c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

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

func (c *oneloginClient) apiPostReq(ctx context.Context, u string, body any) (*http.Request, error) {
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
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", c.apiToken.TokenType, c.apiToken.AccessToken))

	return req, nil
}

func (c *oneloginClient) sendRequest(req *http.Request) (int, []byte, error) {
	res, err := c.httpClient.Do(req)
	if err != nil {
		return -1, nil, err
	}
	defer res.Body.Close()

	b, err := io.ReadAll(io.LimitReader(res.Body, 1024*1024))
	if err != nil {
		return res.StatusCode, nil, err
	}

	return res.StatusCode, b, nil
}

func (c *oneloginClient) sendApiRequest(req *http.Request) ([]byte, error) {
	statusCode, b, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		r := new(oneloginApiError)
		_ = json.Unmarshal(b, r)
		return nil, r
	}

	return b, nil
}

func (c *oneloginClient) sendApiV2Request(req *http.Request) ([]byte, error) {
	statusCode, b, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		r := new(oneloginApiErrorV2)
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

type oneloginAuthReplyV2 struct {
	Data    string `json:"data"`
	Message string `json:"message"`
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

type oneloginSamlReply struct {
	Data    string `json:"data"`
	Message string `json:"message"`
	oneloginAuthData
}

type oneloginMfaFactor struct {
	Id          string `json:"device_id"`
	Type        string `json:"auth_factor_name"`
	TypeName    string `json:"type_display_name"`
	DisplayName string `json:"user_display_name"`
	Default     bool   `json:"default"`
}

type oneloginVerifyFactorRequest struct {
	AppId       string `json:"app_id,omitempty"`
	DeviceId    string `json:"device_id"`
	DoNotNotify bool   `json:"do_not_notify"`
	OtpToken    string `json:"otp_token"`
	StateToken  string `json:"state_token"`
}

type oneloginApiError struct {
	Status *oneloginApiStatus `json:"status"`
}

func (e *oneloginApiError) Error() string {
	if e == nil || e.Status == nil || e.Status.Message == "" {
		return "unexpected OneLogin API response"
	}
	return e.Status.Message
}

type oneloginApiErrorV2 struct {
	Status  int    `json:"statusCode"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

func (e *oneloginApiErrorV2) Error() string {
	return e.Message
}

type mfaVerifier struct {
	send             func(*http.Request) ([]byte, error)
	isInvalidAttempt func(error) bool
	parse            func([]byte) (mfaResult, error)
}

type mfaResult struct {
	pending bool
	token   string
}

var authV1MfaVerifier = mfaVerifier{
	isInvalidAttempt: func(err error) bool {
		var e *oneloginApiError
		return errors.As(err, &e) && e.Status != nil && strings.Contains(e.Status.Message, "Failed authentication with this factor")
	},
	parse: func(b []byte) (mfaResult, error) {
		mfaReply := new(oneloginAuthReply)
		if err := json.Unmarshal(b, mfaReply); err != nil {
			return mfaResult{}, err
		}

		if mfaReply.Status != nil {
			if strings.Contains(strings.ToLower(mfaReply.Status.Message), "pending") {
				return mfaResult{pending: true}, nil
			}

			if strings.EqualFold(mfaReply.Status.Message, "success") && len(mfaReply.Data) > 0 && mfaReply.Data[0] != nil && len(mfaReply.Data[0].SessionToken) > 0 {
				return mfaResult{pending: false, token: mfaReply.Data[0].SessionToken}, nil
			}
		}

		return mfaResult{}, nil
	},
}

var samlV2MfaVerifier = mfaVerifier{
	isInvalidAttempt: func(err error) bool {
		var e *oneloginApiErrorV2
		return errors.As(err, &e) && strings.Contains(e.Message, "Failed authentication with this factor")
	},
	parse: func(b []byte) (mfaResult, error) {
		mfaReply := new(oneloginAuthReplyV2)
		if err := json.Unmarshal(b, mfaReply); err != nil {
			return mfaResult{}, err
		}

		if strings.Contains(strings.ToLower(mfaReply.Message), "pending") {
			return mfaResult{pending: true}, nil
		}

		if strings.EqualFold(mfaReply.Message, "success") && len(mfaReply.Data) > 0 {
			return mfaResult{pending: false, token: mfaReply.Data}, nil
		}

		return mfaResult{}, nil
	},
}
