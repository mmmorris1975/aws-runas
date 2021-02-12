package external

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const keycloakIdentityProvider = "KeycloakIdentityProvider"

type keycloakClient struct {
	*baseClient
}

// NewKeycloakClient returns a new AuthenticationClient capable of handling SAML and WebIdentity operations
// using the Keycloak identity platform.
//
// The 'url' parameter expects the following forms:
// __base URL part__/realms/__realm__ for OAuth/OIDC requests
// __base URL part__/realms/__realm__/protocol/saml/clients/aws for SAML requests
//   (must enable IdP initiated login for client, replace 'aws' part with the local saml client name).
func NewKeycloakClient(url string) (*keycloakClient, error) {
	bc, err := newBaseClient(url)
	if err != nil {
		return nil, err
	}

	c := new(keycloakClient)
	c.baseClient = bc

	// don't chase any redirects talking with Keycloak
	c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return c, nil
}

// Authenticate performs authentication against Keycloak.  This delegates to AuthenticateWithContext using
// context.Background().
func (c *keycloakClient) Authenticate() error {
	return c.AuthenticateWithContext(context.Background())
}

// AuthenticateWithContext performs authentication against Keycloak using the specified Context, which is passed
// along to the underlying HTTP requests.  If necessary, it will prompt for the authentication credentials.
func (c *keycloakClient) AuthenticateWithContext(ctx context.Context) error {
	if err := c.gatherCredentials(); err != nil {
		return err
	}

	return c.auth(ctx)
}

// Identity returns the identity information for the user.
func (c *keycloakClient) Identity() (*identity.Identity, error) {
	return c.identity(keycloakIdentityProvider), nil
}

// IdentityToken calls IdentityTokenWithContext with a background context.
func (c *keycloakClient) IdentityToken() (*credentials.OidcIdentityToken, error) {
	return c.IdentityTokenWithContext(context.Background())
}

// IdentityTokenWithContext retrieves the OIDC Identity Token from Keycloak. This method will automatically prompt for
// authentication if a valid session is not detected.
//
// expected __base-url__/realms/__realm__/protocol/openid-connect/(auth|token).
func (c *keycloakClient) IdentityTokenWithContext(ctx context.Context) (*credentials.OidcIdentityToken, error) {
	pkce, err := newPkceCode()
	if err != nil {
		return nil, err
	}
	authzQS := c.pkceAuthzRequest(pkce.Challenge())
	authUrl := fmt.Sprintf("%s/protocol/openid-connect/auth", c.authUrl.String())

	vals, err := c.oauthAuthorize(authUrl, authzQS, false)
	if err != nil {
		// an error here means we might need to (re-)authenticate
		if strings.Contains(err.Error(), "status 200") {
			u := fmt.Sprintf("%s?%s", authUrl, authzQS.Encode())
			if err = c.formAuth(u); err != nil {
				return nil, err
			}
			return c.IdentityTokenWithContext(ctx)
		}
		return nil, err
	}

	if vals.Get("state") != authzQS.Get("state") {
		return nil, errOauthStateMismatch
	}

	token, err := c.oauthToken(fmt.Sprintf("%s/protocol/openid-connect/token", c.authUrl.String()), vals.Get("code"), pkce.Verifier())
	if err != nil {
		return nil, err
	}

	return token.IdToken, nil
}

// SamlAssertion calls SamlAssertionWithContext using a background context.
func (c *keycloakClient) SamlAssertion() (*credentials.SamlAssertion, error) {
	return c.SamlAssertionWithContext(context.Background())
}

// SamlAssertionWithContext retrieves the SAML Assertion from Keycloak.
// Authentication will automatically be attempted, if required
//
// expected __base-url__/realms/__realm__/protocol/saml/clients/aws (replace 'aws' part with the local AWS saml client name).
func (c *keycloakClient) SamlAssertionWithContext(ctx context.Context) (*credentials.SamlAssertion, error) {
	if err := c.samlRequest(ctx, c.authUrl); err != nil {
		return nil, err
	}

	if c.saml == nil || len(*c.saml) < 1 {
		if err := c.formAuth(c.authUrl.String()); err != nil {
			return nil, err
		}
		return c.SamlAssertionWithContext(ctx)
	}

	return c.saml, nil
}

func (c *keycloakClient) auth(ctx context.Context) error {
	var err error

	if strings.Contains(c.authUrl.String(), "/saml/") {
		_, err = c.SamlAssertionWithContext(ctx)
		return err
	}
	_, err = c.IdentityTokenWithContext(ctx)
	return err
}

func (c *keycloakClient) formAuth(authUrl string) error {
	if err := c.gatherCredentials(); err != nil {
		return err
	}

	submitUrl, creds, err := c.parseForm(authUrl)
	if err != nil {
		return err
	}

	var req *httpRequest
	var res *http.Response
	req, err = newHttpRequest(context.Background(), http.MethodPost, submitUrl.String())
	if err != nil {
		return err
	}

	res, err = checkResponseError(c.httpClient.Do(req.withValues(creds).Request))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if c.isAuthSuccess(res.Cookies()) {
		return nil
	}

	var body []byte
	body, err = ioutil.ReadAll(io.LimitReader(res.Body, 1024*1024))
	if err != nil {
		return err
	}

	// HTTP 200 is returned for auth success, auth failure, and mfa prompting ... need to figure out which this is
	return c.handle200(body)
}

func (c *keycloakClient) parseForm(authUrl string) (*url.URL, url.Values, error) {
	req, err := newHttpRequest(context.Background(), http.MethodGet, authUrl)
	if err != nil {
		return nil, url.Values{}, err
	}

	var res *http.Response
	res, err = checkResponseError(c.httpClient.Do(req.Request))
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, nil, err
	}

	vals := url.Values{}
	form := doc.Find("form").First()
	submitUrl := form.AttrOr("action", "")

	form.Find("input").FilterFunction(func(i int, s *goquery.Selection) bool {
		if t, ok := s.Attr("type"); ok && t != "submit" && t != "reset" {
			return true
		}
		return false
	}).Each(func(i int, s *goquery.Selection) {
		n, _ := s.Attr("name")
		switch strings.ToLower(n) {
		case "username":
			vals.Set(n, c.Username)
		case "password":
			vals.Set(n, c.Password)
		default:
			vals.Set(n, s.AttrOr("value", ""))
		}
	})

	u, _ := url.Parse(submitUrl)
	return u, vals, nil
}

// only a successful authentication attempt (single or multi factor) will set these cookies
// they do not appear to be set during any intermediate steps.
func (c *keycloakClient) isAuthSuccess(cookies []*http.Cookie) bool {
	for _, c := range cookies {
		if c.Name == "KEYCLOAK_IDENTITY" || c.Name == "KEYCLOAK_SESSION" {
			return true
		}
	}
	return false
}

// if there's an input tag with an id of "totp" or "otp", it's an MFA prompt, otherwise return authentication failed.
func (c *keycloakClient) handle200(data []byte) error {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	if err != nil {
		return err
	}

	form := doc.Find("form").First()
	submitUrl := form.AttrOr("action", "")
	mfaField := form.Find("input").FilterFunction(func(i int, s *goquery.Selection) bool {
		if t, ok := s.Attr("name"); ok && strings.HasSuffix(t, "otp") {
			return true
		}
		return false
	}).First().AttrOr("id", "")

	if len(mfaField) > 0 {
		return c.doMfa(submitUrl, mfaField)
	}
	return errors.New("authentication failure")
}

func (c keycloakClient) doMfa(submitUrl, mfaField string) error {
	if len(c.MfaTokenCode) < 1 {
		if c.MfaTokenProvider != nil {
			t, err := c.MfaTokenProvider()
			if err != nil {
				return err
			}
			c.MfaTokenCode = t
		} else {
			return errMfaNotConfigured
		}
	}

	form := url.Values{}
	form.Set(mfaField, c.MfaTokenCode)

	res, err := c.httpClient.PostForm(submitUrl, form) //nolint:noctx
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if c.isAuthSuccess(res.Cookies()) {
		return nil
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("mfa http code %d", res.StatusCode)
	}

	c.MfaTokenCode = ""
	body, err := ioutil.ReadAll(io.LimitReader(res.Body, 1024*1024))
	if err != nil {
		return err
	}
	return c.handle200(body)
}
