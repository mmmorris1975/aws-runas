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
	"strings"
	"time"
)

const (
	// please be constant ... please be constant ... please be constant.
	frOathSvcName = "mfa_oath_authentication"
	frPushSvcName = "mfa_push_authentication"

	forgerockIdentityProvider = "ForgerockIdentityProvider"
)

type forgerockClient struct {
	*baseClient
	baseUrl *url.URL
	realm   string
}

// NewForgerockClient returns a new AuthenticationClient capable of handling SAML and WebIdentity operations
// using the Forgerock identity platform.
//
// The 'url' parameter expects the following forms:
// __base URL part__/oauth2/realms/__realm__ for OAuth/OIDC requests
// __base URL part__/json/realms/__realm__ for SAML bits.
func NewForgerockClient(url string) (*forgerockClient, error) {
	bc, err := newBaseClient(url)
	if err != nil {
		return nil, err
	}

	c := &forgerockClient{baseClient: bc}
	if err = c.parseRealm(); err != nil {
		return nil, err
	}

	if err = c.parseBaseUrl(); err != nil {
		return nil, err
	}

	return c, nil
}

// Authenticate performs authentication against Forgerock.  This delegates to AuthenticateWithContext using
// context.Background().
func (c *forgerockClient) Authenticate() error {
	return c.AuthenticateWithContext(context.Background())
}

// AuthenticateWithContext performs authentication against Forgerock using the specified Context, which is passed
// along to the underlying HTTP requests.  If necessary, it will prompt for the authentication credentials.
func (c *forgerockClient) AuthenticateWithContext(ctx context.Context) error {
	if err := c.gatherCredentials(); err != nil {
		return err
	}

	return c.auth(ctx)
}

// Identity returns the identity information for the user.
func (c *forgerockClient) Identity() (*identity.Identity, error) {
	return c.identity(forgerockIdentityProvider), nil
}

// IdentityToken calls IdentityTokenWithContext with a background context.
func (c *forgerockClient) IdentityToken() (*credentials.OidcIdentityToken, error) {
	return c.IdentityTokenWithContext(context.Background())
}

// IdentityTokenWithContext retrieves the OIDC Identity Token from Forgerock.  The Authenticate() (or AuthenticateWithContext())
// methods must be called before using this method, otherwise an error will be returned.
func (c *forgerockClient) IdentityTokenWithContext(ctx context.Context) (*credentials.OidcIdentityToken, error) {
	pkce, err := newPkceCode()
	if err != nil {
		return nil, err
	}
	authzQS := c.pkceAuthzRequest(pkce.Challenge())

	vals, err := c.oauthAuthorize(fmt.Sprintf("%s/authorize", c.authUrl.String()), authzQS, false)
	if err != nil {
		return nil, err
	}

	if vals.Get("state") != authzQS.Get("state") {
		return nil, errOauthStateMismatch
	}

	token, err := c.oauthToken(fmt.Sprintf("%s/access_token", c.authUrl.String()), vals.Get("code"), pkce.Verifier())
	if err != nil {
		return nil, err
	}

	return token.IdToken, nil
}

// SamlAssertion calls SamlAssertionWithContext using a background context.
func (c *forgerockClient) SamlAssertion() (*credentials.SamlAssertion, error) {
	return c.SamlAssertionWithContext(context.Background())
}

// SamlAssertionWithContext retrieves the SAML Assertion from Forgerock.
// Authentication will automatically be attempted, if required.
func (c *forgerockClient) SamlAssertionWithContext(ctx context.Context) (*credentials.SamlAssertion, error) {
	u, err := url.Parse(fmt.Sprintf("%s/idpssoinit?metaAlias=/%s/saml-idp&spEntityID=%s", c.baseUrl, c.realm, AwsSamlUrn))
	if err != nil {
		return nil, err
	}

	if err = c.samlRequest(ctx, u); err != nil {
		return nil, err
	}

	if c.saml == nil || len(*c.saml) < 1 {
		if err = c.AuthenticateWithContext(ctx); err != nil {
			return nil, err
		}
		return c.SamlAssertionWithContext(ctx)
	}

	return c.saml, nil
}

func (c *forgerockClient) parseRealm() error {
	var err = errors.New("invalid Forgerock Url, must specify a realm")

	p := strings.Split(c.authUrl.Path, "/realms/")
	if len(p) < 2 {
		return err
	}

	r := strings.Split(p[1], "/")
	if len(r) < 1 {
		return err
	}
	c.realm = r[0]

	return nil
}

func (c *forgerockClient) parseBaseUrl() error {
	p := c.authUrl.Path
	sep := ""
	if strings.Contains(p, "/json/") {
		sep = "/json/"
	} else if strings.Contains(p, "/oauth2/") {
		sep = "/oauth2/"
	}

	if len(sep) > 0 {
		parts := strings.Split(c.authUrl.String(), sep)
		u, err := url.Parse(parts[0])
		if err != nil {
			return err
		}
		c.baseUrl = u
		return nil
	}

	return errors.New("invalid Forgerock Url, unable to find base url")
}

// REF: https://backstage.forgerock.com/docs/am/6.5/authorization-guide/index.html#sec-rest-authentication.
func (c *forgerockClient) auth(ctx context.Context) (err error) {
	frAuthUrl := fmt.Sprintf("%s/json/realms/%s/authenticate", c.baseUrl.String(), c.realm)

	switch c.MfaType {
	case MfaTypeNone:
		// no mfa ... require that someone explicitly requests no MFA, instead of this being the default case
		_, err = c.doAuth(ctx, frAuthUrl)
		return
	case MfaTypePush:
		return c.authMfaPush(ctx, frAuthUrl)
	case MfaTypeCode:
		return c.authMfaCode(ctx, frAuthUrl)
	default:
		// attempt some type of MFA, push 1st, then code, if all else fails try no MFA auth and hope for the best
		c.MfaType = MfaTypePush
		if err = c.auth(ctx); err != nil && c.isNoFactorErr(err) {
			c.MfaType = MfaTypeCode
			if err = c.auth(ctx); err != nil && c.isNoFactorErr(err) {
				c.MfaType = MfaTypeNone
				// this may or may not be a good idea
				return c.auth(ctx)
			}
		} else {
			return err
		}
	}

	// Forgerock auth token is carried along as an HTTP cookie
	return nil
}

func (c *forgerockClient) authMfaPush(ctx context.Context, u string) error {
	qs := url.Values{}
	qs.Set("authIndexType", "service")
	qs.Set("authIndexValue", frPushSvcName)

	data, err := c.doAuth(ctx, fmt.Sprintf("%s?%s", u, qs.Encode()))
	if err != nil {
		return err
	}

	body, err := c.handleMfaForm(data)
	if err != nil {
		return err
	}

	fmt.Println("Waiting for Push MFA confirmation")
	for {
		time.Sleep(1250 * time.Millisecond)

		req, err := frAuthReq(ctx, u, bytes.NewReader(body))
		if err != nil {
			return err
		}

		data, err = c.sendApiRequest(req)
		if err != nil {
			if e, ok := err.(*frApiError); ok && e.Code == http.StatusBadRequest {
				// this is actually good, since we sent data to the endpoint which wasn't the expected form,
				// which means it's probably the success message from the service saying MFA is done
				fmt.Println("Push MFA action confirmed")
				return nil
			}
			return err
		}

		body, err = c.handleMfaForm(data)
		if err != nil {
			return err
		}
	}
}

//nolint:gocognit // won't simplify
func (c *forgerockClient) authMfaCode(ctx context.Context, u string) error {
	qs := url.Values{}
	qs.Set("authIndexType", "service")
	qs.Set("authIndexValue", frOathSvcName)

	for {
		data, err := c.doAuth(ctx, fmt.Sprintf("%s?%s", u, qs.Encode()))
		if err != nil {
			return err
		}

		if len(c.MfaTokenCode) < 1 {
			if c.MfaTokenProvider == nil {
				return errMfaNotConfigured
			}

			var t string
			t, err = c.MfaTokenProvider()
			if err != nil {
				return err
			}
			c.MfaTokenCode = t
		}

		body, err := c.handleMfaForm(data)
		if err != nil {
			return err
		}

		req, err := frAuthReq(ctx, u, bytes.NewReader(body))
		if err != nil {
			return err
		}

		_, err = c.sendApiRequest(req)
		if err != nil {
			if e, ok := err.(*frApiError); ok && e.Code == http.StatusUnauthorized {
				c.MfaTokenCode = ""
				fmt.Println("invalid mfa code ... try again")
				continue
			}
			return err
		}
		return nil
	}
}

func (c *forgerockClient) handleMfaForm(data []byte) ([]byte, error) {
	f := new(frMfaPrompt)
	if err := json.Unmarshal(data, f); err != nil {
		return nil, err
	}

	for _, e := range f.Callbacks {
		if e.Type == "PasswordCallback" {
			for _, x := range e.Input {
				if x["name"] == "IDToken1" {
					x["value"] = c.MfaTokenCode
				}
			}
		}
	}

	return json.Marshal(f)
}

func (c *forgerockClient) doAuth(ctx context.Context, u string) ([]byte, error) {
	req, err := frAuthReq(ctx, u, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-OpenAM-Username", rfc2047EncodeString(c.Username))
	req.Header.Set("X-OpenAM-Password", rfc2047EncodeString(c.Password))

	return c.sendApiRequest(req)
}

func (c *forgerockClient) isNoFactorErr(err error) bool {
	if e, ok := err.(*frApiError); ok && e.Code == http.StatusUnauthorized {
		return true
	}
	return false
}

func (c *forgerockClient) sendApiRequest(req *http.Request) ([]byte, error) {
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
		r := new(frApiError)
		_ = json.Unmarshal(b, r)
		return nil, r
	}

	return b, nil
}

// Perform RFC 2047 encoding to support full UTF8 names and passwords
// REF: https://backstage.forgerock.com/docs/am/6.5/authentication-guide/#sec-rest-authentication
func rfc2047EncodeString(s string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(s))
	return fmt.Sprintf("=?UTF-8?B?%s?=", enc)
}

func frAuthReq(ctx context.Context, u string, b io.Reader) (*http.Request, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, u, b)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept-API-Version", "resource=2.0, protocol=1.0")

	return r, nil
}

type frMfaPrompt struct {
	AuthId    string        `json:"authId"`
	Stage     string        `json:"stage"`
	Header    string        `json:"header"`
	Callbacks []*frCallback `json:"callbacks"`
}

type frCallback struct {
	Type   string                   `json:"type"`
	Input  []map[string]interface{} `json:"input"`
	Output []map[string]interface{} `json:"output"`
}

type frApiError struct {
	Code    int    `json:"code"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func (e *frApiError) Error() string {
	return e.Message
}
