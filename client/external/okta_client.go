package external

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const oktaIdentityProvider = "OktaIdentityProvider"

type oktaClient struct {
	*baseClient
	sessionToken string
}

// NewOktaClient returns a new AuthenticationClient capable of handling SAML and WebIdentity operations
// using the Okta identity platform.
func NewOktaClient(url string) (*oktaClient, error) {
	bc, err := newBaseClient(url)
	if err != nil {
		return nil, err
	}

	oc := new(oktaClient)
	oc.baseClient = bc

	return oc, nil
}

// Authenticate performs authentication against OneLogin.  This delegates to AuthenticateWithContext using
// context.Background().
func (c *oktaClient) Authenticate() error {
	return c.AuthenticateWithContext(context.Background())
}

// AuthenticateWithContext performs authentication against Okta using the specified Context, which is passed
// along to the underlying HTTP requests.  If necessary, it will prompt for the authentication credentials.
func (c *oktaClient) AuthenticateWithContext(ctx context.Context) error {
	if err := c.gatherCredentials(); err != nil {
		return err
	}

	res, err := c.auth(ctx)
	if err != nil {
		return err
	}

	c.sessionToken = res.SessionToken
	return nil
}

// Identity returns the identity information for the user.
func (c *oktaClient) Identity() (*identity.Identity, error) {
	return c.identity(oktaIdentityProvider), nil
}

// IdentityToken calls IdentityTokenWithContext with a background context.
func (c *oktaClient) IdentityToken() (*credentials.OidcIdentityToken, error) {
	return c.IdentityTokenWithContext(context.Background())
}

// IdentityTokenWithContext retrieves the OIDC Identity Token from Okta. Authentication will automatically be attempted,
// if required.
func (c *oktaClient) IdentityTokenWithContext(ctx context.Context) (*credentials.OidcIdentityToken, error) {
	pkce, err := newPkceCode()
	if err != nil {
		return nil, err
	}
	authzQS := c.pkceAuthzRequest(pkce.Challenge())

	if len(c.sessionToken) > 0 {
		authzQS.Set("sessionToken", c.sessionToken) // okta specific requirement
	}

	var vals url.Values
	vals, err = c.oauthAuthorize(fmt.Sprintf("%s/v1/authorize", c.authUrl.String()), authzQS, false)
	if err != nil {
		return nil, err
	}

	if len(vals.Get("fromURI")) > 0 {
		// This is an indication that an unauthenticated (or expired session) request was attempted
		if err = c.AuthenticateWithContext(ctx); err != nil {
			return nil, err
		}
		return c.IdentityToken()
	}

	if vals.Get("state") != authzQS.Get("state") {
		return nil, errOauthStateMismatch
	}

	token, err := c.oauthToken(fmt.Sprintf("%s/v1/token", c.authUrl.String()), vals.Get("code"), pkce.Verifier())
	if err != nil {
		return nil, err
	}

	return token.IdToken, nil
}

// SamlAssertion calls SamlAssertionWithContext using a background context.
func (c *oktaClient) SamlAssertion() (*credentials.SamlAssertion, error) {
	return c.SamlAssertionWithContext(context.Background())
}

// SamlAssertionWithContext retrieves the SAML Assertion from Okta.
// Authentication will automatically be attempted, if required.
func (c *oktaClient) SamlAssertionWithContext(ctx context.Context) (*credentials.SamlAssertion, error) {
	u := *c.authUrl
	qs := url.Values{}

	if len(c.sessionToken) > 0 {
		qs.Add("sessionToken", c.sessionToken) // okta specific requirement
	}
	u.RawQuery = qs.Encode()

	if err := c.samlRequest(ctx, &u); err != nil {
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

func (c *oktaClient) auth(ctx context.Context) (*oktaAuthnResponse, error) {
	res, err := c.sendAuthnRequest(ctx)
	if err != nil {
		return nil, err
	}

	switch strings.ToUpper(res.Status) {
	case "SUCCESS":
		return res, nil
	case "MFA_REQUIRED":
		return c.doMfa(ctx, res.StateToken, res.EmbeddedData.MfaFactors)
	default:
		return nil, fmt.Errorf("authentication status %s", res.Status)
	}
}

func (c *oktaClient) sendAuthnRequest(ctx context.Context) (*oktaAuthnResponse, error) {
	creds, err := json.Marshal(map[string]string{
		"username": c.Username,
		"password": c.Password,
	})
	if err != nil {
		return nil, err
	}

	authUrl := fmt.Sprintf("%s://%s/api/v1/authn", c.authUrl.Scheme, c.authUrl.Host)
	res, err := c.sendApiRequst(ctx, authUrl, bytes.NewReader(creds))
	if err != nil {
		return nil, err
	}

	return c.handleAuthResponse(res)
}

func (c *oktaClient) doMfa(ctx context.Context, stateToken string, factors []*oktaMfaFactor) (*oktaAuthnResponse, error) {
	// don't try to short-circuit with a len(factors) == 1 case, since it could be a factor we dont' support
	// we need to loop through the provided factors, and choose only the supported types
	index := make(map[string]int)
	for i, f := range factors {
		if f.FactorType == "push" || strings.HasPrefix(f.FactorType, "token") {
			index[f.FactorType] = i
		}
	}

	switch len(index) {
	case 0:
		// fall through
	case 1:
		for _, v := range index {
			return c.handleMfa(ctx, stateToken, factors[v])
		}
	default:
		for _, e := range []string{"push", "token:software:totp", "token:hotp", "token"} {
			if v, ok := index[e]; ok {
				return c.handleMfa(ctx, stateToken, factors[v])
			}
		}
	}

	return nil, errMfaNotConfigured
}

func (c *oktaClient) handleMfa(ctx context.Context, stateToken string, factor *oktaMfaFactor) (*oktaAuthnResponse, error) {
	verifyUrl := factor.Links["verify"].Href

	switch factor.FactorType {
	case "push":
		// send push notification
		body, _ := json.Marshal(oktaMfaResponse{Token: stateToken})

		res, err := c.sendApiRequst(ctx, verifyUrl, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}

		r, err := c.handleAuthResponse(res)
		if err != nil {
			return nil, err
		}

		// handle push response
		return c.handlePushMfa(ctx, r)
	case "token", "token:hotp", "token:software:totp":
		return c.handleTokenMfa(ctx, stateToken, verifyUrl)
	default:
		return nil, fmt.Errorf("unsupported MFA Type: %s", factor.FactorType)
	}
}

func (c *oktaClient) handlePushMfa(ctx context.Context, res *oktaAuthnResponse) (*oktaAuthnResponse, error) {
	var err error

	fmt.Print("Waiting for Push MFA ")

	for strings.EqualFold(res.Status, "MFA_CHALLENGE") && strings.EqualFold(res.FactorResult, "WAITING") {
		var nextUrl string
		if v, ok := res.Links["next"].(map[string]interface{}); ok {
			nextUrl, _ = v["href"].(string)
		}

		body, _ := json.Marshal(oktaMfaResponse{Token: res.StateToken})

		time.Sleep(1250 * time.Millisecond)
		fmt.Print(".")

		var r *http.Response
		r, err = c.sendApiRequst(ctx, nextUrl, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}

		res, err = c.handleAuthResponse(r)
		if err != nil {
			return nil, err
		}
	}
	return res, err
}

func (c *oktaClient) handleTokenMfa(ctx context.Context, stateToken, url string) (*oktaAuthnResponse, error) {
	if len(c.MfaTokenCode) < 1 {
		if c.MfaTokenProvider != nil {
			t, err := c.MfaTokenProvider()
			if err != nil {
				return nil, err
			}
			c.MfaTokenCode = t
		} else {
			return nil, errMfaNotConfigured
		}
	}

	mfa := oktaMfaResponse{Token: stateToken, Code: c.MfaTokenCode}
	data, _ := json.Marshal(mfa)

	res, err := c.sendApiRequst(ctx, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	// this is a re-tryable error (re-prompt for mfa code)
	if res.StatusCode != http.StatusOK {
		_ = res.Body.Close()
		c.MfaTokenCode = ""
		fmt.Println("invalid mfa code ... try again")
		return c.handleTokenMfa(ctx, stateToken, url)
	}

	return c.handleAuthResponse(res)
}

func (c *oktaClient) sendApiRequst(ctx context.Context, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return c.httpClient.Do(req)
}

func (c *oktaClient) handleAuthResponse(res *http.Response) (*oktaAuthnResponse, error) {
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	// any non-200 status code is bad (invalid creds, locked out), reason will be provided in response body
	if res.StatusCode != http.StatusOK {
		r := new(oktaApiError)
		_ = json.Unmarshal(body, r)
		return nil, r
	}

	or := new(oktaAuthnResponse)
	if err := json.Unmarshal(body, or); err != nil {
		return nil, err
	}
	return or, nil
}

type oktaAuthnResponse struct {
	Status       string                 `json:"status"`
	SessionToken string                 `json:"sessionToken,omitempty"`
	StateToken   string                 `json:"stateToken,omitempty"`
	FactorResult string                 `json:"factorResult"`
	Links        map[string]interface{} `json:"_links"`
	EmbeddedData struct {
		MfaFactors []*oktaMfaFactor `json:"factors"`
	} `json:"_embedded,omitempty"`
}

type oktaMfaFactor struct {
	Id         string `json:"id"`
	FactorType string `json:"factorType"`
	Provider   string `json:"provider"`
	Links      map[string]struct {
		Href string `json:"href"`
	} `json:"_links"`
}

type oktaMfaResponse struct {
	Token string `json:"stateToken"`
	Code  string `json:"passCode,omitempty"`
}

type oktaApiError struct {
	Code    string `json:"errorCode"`
	Message string `json:"errorSummary"`
	Id      string `json:"errorId"`
}

func (e *oktaApiError) Error() string {
	return e.Message
}
