package saml

import (
	"aws-runas/lib/identity"
	"encoding/base64"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type keycloakSamlClient struct {
	*SamlClient
	realm             string
	baseUrl           *url.URL
	clientId          string
	decodedAwsSamlDoc string
}

// NewKeycloakSamlClient creates a Keycloak aware SAML client using information supplied by the provided metadata URL
func NewKeycloakSamlClient(mdUrl string) (*keycloakSamlClient, error) {
	bsc, err := NewSamlClient(mdUrl)
	if err != nil {
		return nil, err
	}
	bsc.MfaType = MfaTypeAuto

	u, err := url.Parse(bsc.entityId)
	if err != nil {
		return nil, err
	}

	c := &keycloakSamlClient{
		SamlClient: bsc,
		realm:      parseRealm(u),
		baseUrl:    u,
		clientId:   "account", // fixme possibly replace with AWS URN
	}

	return c, nil
}

// Authenticate handles authentication against a Keycloak compatible identity provider
func (c *keycloakSamlClient) Authenticate() error {
	if err := c.GatherCredentials(); err != nil {
		return nil
	}

	return c.auth()
}

// Saml performs a request to the Keycloak server's SAML endpoint for the requested Service Provider ID
func (c *keycloakSamlClient) Saml(spId string) (string, error) {
	u, err := url.Parse(fmt.Sprintf("%s/protocol/saml", c.baseUrl))
	if err != nil {
		return "", err
	}

	doc, err := c.SamlRequest(u)
	if err != nil {
		return "", err
	}

	return getSamlResponse(doc), nil
}

// AwsSaml performs a SAML request using the well known AWS service provider URN.  The result of this request is cached
// in memory to avoid repeated requests to the Keycloak endpoint.
func (c *keycloakSamlClient) AwsSaml() (string, error) {
	if len(c.rawSamlResponse) > 0 {
		return c.rawSamlResponse, nil
	}

	s, err := c.Saml(AwsUrn)
	if err != nil {
		return "", err
	}
	c.rawSamlResponse = s

	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	c.decodedAwsSamlDoc = string(b)

	return s, nil
}

// GetIdentity retrieves the RoleSessionName attribute from the data returned by AwsSaml()
func (c *keycloakSamlClient) GetIdentity() (*identity.Identity, error) {
	d, err := c.getDecodedAwsSamlDoc()
	if err != nil {
		return nil, err
	}

	return getAwsSamlIdentity(d)
}

// Roles retrieves the list of roles available to user from the data returned by AwsSaml()
func (c *keycloakSamlClient) Roles(user ...string) (identity.Roles, error) {
	d, err := c.getDecodedAwsSamlDoc()
	if err != nil {
		return nil, err
	}

	return getAwsSamlRoles(d)
}

// GetSessionDuration retrieves the SessionDuration attribute from the data returned by AwsSaml()
func (c *keycloakSamlClient) GetSessionDuration() (int64, error) {
	d, err := c.getDecodedAwsSamlDoc()
	if err != nil {
		return -1, err
	}

	return getAwsSessionDuration(d)
}

func (c *keycloakSamlClient) auth() error {
	u, err := c.getAuthUrl()
	if err != nil {
		if t, ok := err.(*errAuthFailure); ok && t.code == 0 {
			return nil
		}
		return err
	}

	creds := url.Values{}
	creds.Set("username", c.Username)
	creds.Set("password", c.Password)

	res, err := c.httpClient.PostForm(u.String(), creds)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusFound {
			// this is success
			return nil
		}
		return new(errAuthFailure).WithCode(res.StatusCode)
	}

	// HTTP 200 could either mean we're being prompted for MFA, or the authentication failed
	// Keycloak only supports code-based MFA, so don't test for configured MfaType
	return c.handle200(res.Body)
}

func (c *keycloakSamlClient) getAuthUrl() (*url.URL, error) {
	u := fmt.Sprintf("%s/protocol/openid-connect/auth?client_id=%s&response_type=none", c.baseUrl, c.clientId)
	res, err := c.httpClient.Get(u)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusFound {
			return nil, new(errAuthFailure).WithCode(0)
		}
		return nil, new(errAuthFailure).WithCode(res.StatusCode)
	}

	doc, err := html.Parse(res.Body)
	if err != nil {
		return nil, err
	}

	var authUrl string
	var f func(n *html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			for _, v := range n.Attr {
				if v.Key == "action" {
					authUrl = v.Val
					return
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return url.Parse(authUrl)
}

func (c *keycloakSamlClient) handle200(body io.ReadCloser) error {
	doc, err := html.Parse(body)
	if err != nil {
		return err
	}

	var authUrl string
	var isMfa bool
	var f func(n *html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if n.Data == "form" {
				for _, v := range n.Attr {
					if v.Key == "action" {
						authUrl = v.Val
						break
					}
				}
			}

			if n.Data == "input" {
				for _, v := range n.Attr {
					if v.Key == "id" && v.Val == "totp" {
						isMfa = true
						return
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	if isMfa {
		return c.doMfa(authUrl)
	}

	return new(errAuthFailure).WithCode(http.StatusUnauthorized)
}

func (c *keycloakSamlClient) doMfa(authUrl string) error {
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

	form := url.Values{}
	form.Set("login", "Log+In")
	form.Set("totp", c.MfaToken)

	res, err := c.httpClient.PostForm(authUrl, form)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusFound {
			// this is success
			return nil
		}
		return new(errAuthFailure).WithCode(res.StatusCode)
	}

	c.MfaToken = ""
	fmt.Println("invalid mfa code ... try again")
	return c.handle200(res.Body)
}

func (c *keycloakSamlClient) getDecodedAwsSamlDoc() (string, error) {
	var err error

	if len(c.decodedAwsSamlDoc) < 1 {
		if _, err = c.AwsSaml(); err != nil {
			return "", err
		}
	}

	return c.decodedAwsSamlDoc, nil
}

func parseRealm(u *url.URL) string {
	p := strings.Split(u.Path, "/")
	return p[len(p)-1]
}
