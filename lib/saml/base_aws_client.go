package saml

import (
	"aws-runas/lib/credentials"
	"aws-runas/lib/identity"
	"encoding/base64"
	"fmt"
	"golang.org/x/net/html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// BaseAwsClient is the base AwsClient type which can handle much of the SAML interaction, once a client is authenticated
type BaseAwsClient struct {
	authUrl          *url.URL
	baseUrl          *url.URL
	httpClient       *http.Client
	rawSamlResponse  string
	decodedSaml      string
	Username         string
	Password         string
	CredProvider     func(string, string) (string, string, error)
	MfaTokenProvider func() (string, error)
	MfaType          string
	MfaToken         string
}

func newBaseAwsClient(authUrl string) (*BaseAwsClient, error) {
	u, err := url.Parse(authUrl)
	if err != nil {
		return nil, err
	}

	if !strings.Contains(u.Scheme, "http") {
		return nil, fmt.Errorf("not a valid URL")
	}

	c := BaseAwsClient{
		authUrl:          u,
		CredProvider:     credentials.StdinCredProvider,
		MfaTokenProvider: credentials.StdinMfaTokenProvider,
		MfaType:          MfaTypeAuto,
	}
	c.setHttpClient()

	return &c, nil
}

// Client returns the concrete AwsClient type to allow attributes to be exposed through the Client interface
func (c *BaseAwsClient) Client() *BaseAwsClient {
	return c
}

// SetCookieJar configures the HTTP client's cookie jar so that cookies used during the SAML http requests are persisted.
// If not set, the default Golang cookie jar is used to store the values in memory.
func (c *BaseAwsClient) SetCookieJar(jar http.CookieJar) {
	c.setHttpClient()
	c.httpClient.Jar = jar
}

// GetIdentity retrieves the RoleSessionName attribute from the data returned by AwsSaml()
func (c *BaseAwsClient) GetIdentity() (*identity.Identity, error) {
	return c.getIdentity()
}

// Roles retrieves the list of roles available to user from the data returned by AwsSaml()
func (c *BaseAwsClient) Roles(user ...string) (identity.Roles, error) {
	return c.roles()
}

// RoleDetails retrieves the IAM Role and SAML provider principal ARN from the data returned by AwsSaml()
func (c *BaseAwsClient) RoleDetails() (*RoleDetails, error) {
	return c.roleDetails()
}

// GetSessionDuration retrieves the SessionDuration attribute from the data returned by AwsSaml()
func (c *BaseAwsClient) GetSessionDuration() (int64, error) {
	return c.getSessionDuration()
}

func (c *BaseAwsClient) setHttpClient() {
	if c.httpClient == nil {
		hc := new(http.Client)
		hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects, just return 1st response
			return http.ErrUseLastResponse
		}

		c.httpClient = hc
	}
}

func (c *BaseAwsClient) getIdentity() (*identity.Identity, error) {
	if err := c.decodeSaml(); err != nil {
		return nil, err
	}

	re, err := regexp.Compile(`RoleSessionName.*?>([\w_=,.@-]+)<`)
	if err != nil {
		return nil, err
	}

	m := re.FindStringSubmatch(c.decodedSaml)
	if len(m) < 2 {
		return nil, fmt.Errorf("unable to find RoleSessionName attribute in SAML doc")
	}

	return &identity.Identity{
		IdentityType: "user",
		Username:     m[1],
		Provider:     IdentityProviderSaml,
	}, nil
}

func (c *BaseAwsClient) roleDetails() (*RoleDetails, error) {
	rd := new(RoleDetails)
	rd.details = make(map[string]string)

	if err := c.decodeSaml(); err != nil {
		return nil, err
	}

	re, err := regexp.Compile(`>(arn:aws:iam::\d+:(?:role|saml-provider)/.*?),(arn:aws:iam::\d+:(?:role|saml-provider)/.*?)<`)
	if err != nil {
		return nil, err
	}

	m := re.FindAllStringSubmatch(c.decodedSaml, -1)
	if m != nil {
		for _, r := range m {
			if strings.Contains(":role/", r[1]) {
				rd.details[r[1]] = r[2]
			} else {
				rd.details[r[2]] = r[1]
			}
		}
	}

	return rd, nil
}

func (c *BaseAwsClient) roles() (identity.Roles, error) {
	rd, err := c.roleDetails()
	if err != nil {
		return nil, err
	}
	return rd.Roles(), nil
}

func (c *BaseAwsClient) getSessionDuration() (int64, error) {
	if err := c.decodeSaml(); err != nil {
		return -1, err
	}

	re, err := regexp.Compile(`SessionDuration.*?>(\d+)<`)
	if err != nil {
		return -1, err
	}

	m := re.FindStringSubmatch(c.decodedSaml)
	if len(m) < 2 {
		return -1, fmt.Errorf("unable to find SessionDuration attribute in SAML doc")
	}

	return strconv.ParseInt(m[1], 0, 64)
}

func (c *BaseAwsClient) decodeSaml() error {
	if len(c.decodedSaml) < 1 && len(c.rawSamlResponse) > 0 {
		b, err := base64.StdEncoding.DecodeString(c.rawSamlResponse)
		if err != nil {
			return err
		}
		c.decodedSaml = string(b)
	}
	return nil
}

func (c *BaseAwsClient) samlRequest(u *url.URL) error {
	r, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}

	res, err := c.httpClient.Do(r)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("SAML request http status code: %d", res.StatusCode)
	}

	doc, err := html.Parse(res.Body)
	if err != nil {
		return err
	}

	c.rawSamlResponse = c.handleSamlResponse(doc)
	if len(c.rawSamlResponse) < 1 {
		return fmt.Errorf("did not receive a valid SAML response")
	}

	return c.decodeSaml()
}

func (c *BaseAwsClient) handleSamlResponse(doc *html.Node) string {
	inputs := make(map[string]string)

	var f func(n *html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			name := ""
			for _, a := range n.Attr {
				if a.Key == "name" {
					name = a.Val
				}

				if a.Key == "value" {
					inputs[name] = a.Val
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return inputs["SAMLResponse"]
}

func (c *BaseAwsClient) gatherCredentials() error {
	var err error

	u := c.Username
	p := c.Password
	if len(u) < 1 || len(p) < 1 {
		u, p, err = c.CredProvider(u, p)
		if err != nil {
			return err
		}
		c.Username = u
		c.Password = p
	}

	m := c.MfaToken
	if c.MfaType == MfaTypeCode && len(m) < 1 && c.MfaTokenProvider != nil {
		m, err = c.MfaTokenProvider()
		if err != nil {
			return err
		}
		c.MfaToken = m
	}

	return nil
}
