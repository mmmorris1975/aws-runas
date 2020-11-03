package external

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/credentials/helpers"
	"github.com/mmmorris1975/aws-runas/identity"
	"github.com/mmmorris1975/aws-runas/shared"
	"golang.org/x/net/publicsuffix"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

type baseClient struct {
	OidcClientConfig
	authUrl    *url.URL
	httpClient *http.Client
	saml       *credentials.SamlAssertion
}

func newBaseClient(u string) (*baseClient, error) {
	authUrl, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(authUrl.Scheme, "http") {
		return nil, errors.New("invalid client URL")
	}

	c := &baseClient{
		authUrl: authUrl,
	}
	c.MfaTokenProvider = helpers.NewMfaTokenProvider(os.Stdin).ReadInput
	c.CredentialInputProvider = helpers.NewUserPasswordInputProvider(os.Stdin).ReadInput
	c.MfaType = MfaTypeAuto
	c.setHttpClient()
	c.Logger = new(shared.DefaultLogger)

	return c, nil
}

// SetCookieJar updates this clients HTTP cookie storage to use the provides http.CookieJar.
func (c *baseClient) SetCookieJar(jar http.CookieJar) {
	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}
	c.httpClient.Jar = jar
}

// Roles retrieves the available roles for SamlClients.  Attempting to call this method
// against an Oauth/OIDC client will return an error.
func (c *baseClient) Roles(user ...string) (*identity.Roles, error) {
	if len(c.ClientId) > 0 && len(c.RedirectUri) > 0 {
		return nil, errors.New("OIDC clients are not role aware")
	}

	rd, err := c.saml.RoleDetails()
	if err != nil {
		return nil, err
	}

	roles := identity.Roles(rd.Roles())
	return &roles, nil
}

func (c *baseClient) setHttpClient() {
	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}

	if c.httpClient.Jar == nil {
		// this never returns an error, so don't bother checking
		c.httpClient.Jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	}
}

func (c *baseClient) samlRequest(ctx context.Context, u *url.URL) error {
	if c.saml != nil && len(*c.saml) > 0 {
		t, err := c.saml.ExpiresAt()
		if err != nil {
			return err
		}

		if t.After(time.Now()) {
			return nil
		}
	}

	// must use http client which will not auto-follow redirects ... apparently except for okta (maybe onelogin?)
	// just be sure to update any non-redirect cases in the individual client implementations by
	// setting c.httpClient.CheckRedirect as below
	// httpClient := http.Client{
	//	Jar: c.httpClient.Jar,
	//	CheckRedirect: func(req *http.Request, via []*http.Request) error {
	//		return http.ErrUseLastResponse
	//	},
	// }

	res, err := c.httpClient.Get(u.String())
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("SAML request http status code: %d", res.StatusCode)
	}

	return c.handleSamlResponse(res.Body)
}

func (c *baseClient) handleSamlResponse(r io.Reader) error {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return err
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		if a, ok := s.Attr("name"); ok && a == "SAMLResponse" {
			v, _ := s.Attr("value")
			saml := credentials.SamlAssertion(v)
			c.saml = &saml
		}
	})

	return nil
}

func (c *baseClient) identity(provider string) *identity.Identity {
	if len(c.Username) < 1 {
		_ = c.gatherCredentials()
	}

	id := &identity.Identity{
		IdentityType: "user",
		Provider:     provider,
		Username:     c.Username,
	}

	if c.saml != nil && len(*c.saml) > 0 {
		user, err := c.saml.RoleSessionName()
		if err != nil {
			return id
		}
		id.Username = user
	}

	return id
}

func (c *baseClient) pkceAuthzRequest(pkceChallenge string) url.Values {
	state := fmt.Sprintf("%d.%d.%s", time.Now().UnixNano(), rand.Int(), pkceChallenge) //nolint:gosec  // no need for crypto-strength random

	qs := url.Values{}
	qs.Set("client_id", c.ClientId)
	qs.Set("code_challenge", pkceChallenge)
	qs.Set("code_challenge_method", "S256")
	qs.Set("redirect_uri", c.RedirectUri)
	qs.Set("response_type", "code")

	// recommended per OpenID spec, required for Okta
	qs.Set("state", base64.RawStdEncoding.EncodeToString([]byte(state)))

	qs.Set("scope", "openid")
	for _, v := range c.Scopes {
		qs.Add("scope", v)
	}

	return qs
}

func (c *baseClient) oauthAuthorize(ep string, data url.Values, followRedirect bool) (url.Values, error) {
	// make sure we use an appropriate http.Client based on the value of followRedirect.
	httpClient := c.httpClient
	if followRedirect {
		if httpClient.CheckRedirect != nil {
			httpClient = new(http.Client)
			httpClient.Jar = c.httpClient.Jar
		}
	} else {
		if httpClient.CheckRedirect == nil {
			httpClient = &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
				Jar: c.httpClient.Jar,
			}
		}
	}

	u, err := url.Parse(ep)
	if err != nil {
		return nil, err
	}
	u.RawQuery = data.Encode()

	res, err := httpClient.Get(u.String())
	if err != nil {
		// if followRedirect == true, and the IdP is (correctly!) configured to return an invalid/unreachable value
		// for the redirect URI, we'll end up here.  Intercept the error and return the token data.  Anything not
		// matching this criteria is handled as an actual failure
		if e, ok := err.(*url.Error); ok {
			if strings.HasPrefix(e.URL, c.RedirectUri) {
				redirUri, _ := url.Parse(e.URL)
				return redirUri.Query(), nil
			}
		}
		return nil, err
	}
	defer res.Body.Close()

	// we should only ever get here if followRedirect == false, in which case the status code should
	// always be HTTP 302, but better safe than sorry
	if res.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("http status %s", res.Status)
	}

	redir, err := res.Location()
	if err != nil {
		return nil, err
	}
	return redir.Query(), nil
}

func (c *baseClient) oauthToken(ep, code, verifier string) (*oauthToken, error) {
	data := url.Values{}
	data.Set("client_id", c.ClientId)
	data.Set("code", code)
	data.Set("code_verifier", verifier)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", c.RedirectUri)

	res, err := c.httpClient.PostForm(ep, data)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(io.LimitReader(res.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %s", res.Status)
	}

	token := new(oauthToken)
	if err := json.Unmarshal(body, token); err != nil {
		return nil, err
	}
	return token, nil
}

func (c *baseClient) gatherCredentials() error {
	var err error

	u := c.Username
	p := c.Password
	if len(u) < 1 || len(p) < 1 {
		u, p, err = c.CredentialInputProvider(u, p)
		if err != nil {
			return err
		}
		c.Username = u
		c.Password = p
	}

	m := c.MfaTokenCode
	if c.MfaType == MfaTypeCode && len(m) < 1 && c.MfaTokenProvider != nil {
		m, err = c.MfaTokenProvider()
		if err != nil {
			return err
		}
		c.MfaTokenCode = m
	}

	return nil
}
