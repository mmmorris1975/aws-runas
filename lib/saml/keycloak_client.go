package saml

import (
	"golang.org/x/net/html"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type keycloakSamlClient struct {
	*BaseAwsClient
	realm    string
	clientId string
}

// NewKeycloakSamlClient creates a Keycloak aware SAML client using authUrl as the authentication endpoint
// Keycloak convention for this is along the lines of __base-url__/realms/__realm-name__/protocol/saml/clients/__client-id__
// This is the same URL which is used to "do the SAML" between Keycloak and AWS
func NewKeycloakSamlClient(authUrl string) (*keycloakSamlClient, error) {
	bsc, err := newBaseAwsClient(authUrl)
	if err != nil {
		return nil, err
	}
	bsc.MfaType = MfaTypeAuto

	c := &keycloakSamlClient{BaseAwsClient: bsc}
	//c.parseBaseUrl()
	//c.parseRealm()
	//c.parseClientId()

	return c, nil
}

func (c *keycloakSamlClient) parseBaseUrl() {
	s := strings.Split(c.authUrl.String(), "/protocol/")
	u, _ := url.Parse(s[0])
	c.baseUrl = u
}

func (c *keycloakSamlClient) parseRealm() {
	p := strings.Split(c.authUrl.Path, "/realms/")
	s := strings.Split(p[1], "/")
	c.realm = s[0]
}

func (c *keycloakSamlClient) parseClientId() {
	q := c.authUrl.Query().Get("client_id")
	if len(q) < 1 {
		s := strings.Split(c.authUrl.Path, "/clients/")
		q = s[1]
	}
	c.clientId = q
}

// Authenticate handles authentication against a Keycloak compatible identity provider
func (c *keycloakSamlClient) Authenticate() error {
	if err := c.gatherCredentials(); err != nil {
		return nil
	}

	return c.auth()
}

// AwsSaml performs a SAML request using the auth URL provided at the start.  The result of this request is cached
// in memory to avoid repeated requests to the Keycloak endpoint.
func (c *keycloakSamlClient) AwsSaml() (string, error) {
	if len(c.rawSamlResponse) > 0 {
		return c.rawSamlResponse, nil
	}

	if err := c.samlRequest(c.authUrl); err != nil {
		return "", err
	}

	return c.rawSamlResponse, nil
}

func (c *keycloakSamlClient) auth() error {
	u, fields, err := c.getAuthUrl()
	if err != nil {
		if t, ok := err.(*errAuthFailure); ok && t.code == 0 {
			return nil
		}
		return err
	}

	for key := range fields {
		if strings.ToLower(key) == "username" {
			fields.Set(key, c.Username)
		} else if strings.ToLower(key) == "password" {
			fields.Set(key, c.Password)
		}
	}

	res, err := c.httpClient.PostForm(u.String(), fields)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return new(errAuthFailure).WithCode(res.StatusCode).WithText("Authentication failed")
	}

	// HTTP 200 could either mean we've received a SAMLResponse after a successful authentication, we're being prompted
	// for MFA, or the authentication failed. Keycloak only supports code-based MFA, so don't test for configured MfaType
	return c.handle200(res.Body)
}

func (c *keycloakSamlClient) getAuthUrl() (*url.URL, url.Values, error) {
	res, err := c.httpClient.Get(c.authUrl.String())
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusFound {
			return nil, nil, new(errAuthFailure).WithCode(0).WithText("Auth URL redirect")
		}
		return nil, nil, new(errAuthFailure).WithCode(res.StatusCode).WithText("Failure retrieving auth url")
	}

	doc, err := html.Parse(res.Body)
	if err != nil {
		return nil, nil, err
	}

	var authUrl string
	fields := url.Values{}
	var f func(n *html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			for _, v := range n.Attr {
				if v.Key == "action" {
					authUrl = v.Val
					break
				}
			}
		}

		if n.Type == html.ElementNode && n.Data == "input" {
			var attr, val string
			use := true
			for _, v := range n.Attr {
				if v.Key == "type" && (v.Val == "submit" || v.Val == "reset") {
					use = false
					break
				} else if v.Key == "name" {
					attr = v.Val
				} else if v.Key == "value" {
					val = v.Val
				}
			}

			if use {
				fields.Add(attr, val)
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	u, err := url.Parse(authUrl)
	if err != nil {
		return nil, nil, err
	}

	return u, fields, nil
}

func (c *keycloakSamlClient) handle200(body io.ReadCloser) error {
	doc, err := html.Parse(body)
	if err != nil {
		return err
	}

	c.rawSamlResponse = c.handleSamlResponse(doc)
	if len(c.rawSamlResponse) > 0 {
		return nil
	}

	var authUrl, mfaField string
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
					if v.Key == "id" && (v.Val == "totp" || v.Val == "otp") {
						isMfa = true
						mfaField = v.Val
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
		return c.doMfa(authUrl, mfaField)
	}

	return new(errAuthFailure).WithCode(http.StatusUnauthorized).WithText("Invalid authentication response")
}

func (c *keycloakSamlClient) doMfa(authUrl, mfaField string) error {
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
	form.Set(mfaField, c.MfaToken)

	res, err := c.httpClient.PostForm(authUrl, form)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return new(errAuthFailure).WithCode(res.StatusCode).WithText("MFA failed")
	}

	c.MfaToken = ""
	return c.handle200(res.Body)
}
