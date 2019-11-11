package saml

import (
	"aws-runas/lib/credentials"
	"aws-runas/lib/identity"
	"encoding/xml"
	"fmt"
	"github.com/russellhaering/gosaml2/types"
	"golang.org/x/net/html"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

const (
	// MfaTypeNone indicates that no MFA should be attempted regardless of the state of other MFA configuration
	MfaTypeNone = "none"
	// MfaTypeAuto indicates that the MFA type to use should be auto detected (as determined by each concrete provider)
	MfaTypeAuto = "auto"
	// MfaTypeCode indicates the use of MFA token/otp codes
	MfaTypeCode = "code"
	// MfaTypePush indicates the use of MFA push notifications
	MfaTypePush = "push"
	// IdentityProviderSaml is the name which names the the provider which resolved the identity
	IdentityProviderSaml = "SAMLIdentityProvider"
)

type SamlClient struct {
	mdUrl            *url.URL
	ssoUrl           *url.URL
	entityId         string
	httpClient       *http.Client
	rawSamlResponse  string
	Username         string
	Password         string
	CredProvider     func(string, string) (string, string, error)
	MfaTokenProvider func() (string, error)
	MfaType          string
	MfaToken         string
}

// NewSamlClient builds a basic SAML client based off of information retrieved from a request to the
// provided SAML metadata URL.  By default, it will prompt for credentials and MFA information (if required)
// by prompting for the information on the terminal, and reading the values from os.Stdin
func NewSamlClient(md string) (*SamlClient, error) {
	mdUrl, err := url.Parse(md)
	if err != nil {
		return nil, err
	}

	entityDesc, err := fetchIdpMetadata(mdUrl.String())
	if err != nil {
		return nil, err
	}

	ssoUrl, err := url.Parse(entityDesc.IDPSSODescriptor.SingleSignOnServices[0].Location)
	if err != nil {
		return nil, err
	}

	hc := new(http.Client)
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Don't follow redirects, just return 1st response
		return http.ErrUseLastResponse
	}

	return &SamlClient{
		mdUrl:            mdUrl,
		ssoUrl:           ssoUrl,
		entityId:         entityDesc.EntityID,
		httpClient:       hc,
		CredProvider:     credentials.StdinCredProvider,
		MfaTokenProvider: credentials.StdinMfaTokenProvider,
		MfaType:          MfaTypeAuto,
	}, nil
}

// Client returns the concrete SamlClient type to allow attributes to be exposed through the Client interface
func (c *SamlClient) Client() *SamlClient {
	return c
}

// SetCookieJar configures the HTTP client's cookie jar so that cookies used during the SAML http requests are persisted.
// If not set, the default Golang cookie jar is used to store the values in memory.
func (c *SamlClient) SetCookieJar(j http.CookieJar) {
	c.httpClient.Jar = j
}

// SamlRequest performs HTTP GET requests against the specified URL and returns the body as a parsed
// *html.Node type.
func (c *SamlClient) SamlRequest(u *url.URL) (*html.Node, error) {
	r, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	res, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status code: %d", res.StatusCode)
	}

	doc, err := html.Parse(res.Body)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

// GatherCredentials is responsible for obtaining the necessary username, password, and optionally MFA token value
// necessary to perform authentication with the SAML identity provider.  If necessary, the functions defined by this
// object's CredProvider and MfaTokenProvider settings are used to collect the information.
func (c *SamlClient) GatherCredentials() error {
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
	if c.MfaType == MfaTypeCode && len(m) < 1 {
		m, err = c.MfaTokenProvider()
		if err != nil {
			return err
		}
		c.MfaToken = m
	}

	return nil
}

func getAwsSamlIdentity(d string) (*identity.Identity, error) {
	re, err := regexp.Compile(`RoleSessionName.*?>([\w_=,.@-]+)<`)
	if err != nil {
		return nil, err
	}

	m := re.FindStringSubmatch(d)
	if len(m) < 2 {
		return nil, fmt.Errorf("unable to find RoleSessionName attribute in SAML doc")
	}

	return &identity.Identity{
		IdentityType: "user",
		Username:     m[1],
		Provider:     IdentityProviderSaml,
	}, nil
}

func getAwsSamlRoles(d string) (identity.Roles, error) {
	roles := make([]string, 0)

	re, err := regexp.Compile(`>(arn:aws:iam::\d+:role/.*?),(arn:aws:iam::\d+:saml-provider/.*?)<`)
	if err != nil {
		return nil, err
	}

	m := re.FindAllStringSubmatch(d, -1)
	if m != nil {
		for _, r := range m {
			roles = append(roles, r[1])
		}
	}

	return roles, nil
}

func getAwsSessionDuration(d string) (int64, error) {
	re, err := regexp.Compile(`SessionDuration.*?>(\d+)<`)
	if err != nil {
		return -1, err
	}

	m := re.FindStringSubmatch(d)
	if len(m) < 2 {
		return -1, fmt.Errorf("unable to find SessionDuration attribute in SAML doc")
	}

	return strconv.ParseInt(m[1], 0, 64)
}

func getSamlResponse(doc *html.Node) string {
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

func fetchIdpMetadata(u string) (*types.EntityDescriptor, error) {
	res, err := http.Get(u)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata request returned http status %d", res.StatusCode)
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	md := new(EntitiesDescriptor)
	if err := xml.Unmarshal(b, md); err != nil {
		// not an <EntitiesDescriptor>, try just <EntityDescriptor> before failing
		ed := new(types.EntityDescriptor)
		if err := xml.Unmarshal(b, ed); err != nil {
			return nil, err
		}
		return ed, nil
	}

	return md.EntityIDs[0], nil
}

// EntitiesDescriptor is an XML container element for 1 or more EntityDescriptor. Not used for Forgerock, but seen on Keycloak
type EntitiesDescriptor struct {
	XMLName   xml.Name                  `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
	Name      string                    `xml:"Name,attr"`
	EntityIDs []*types.EntityDescriptor `xml:"EntityDescriptor"`
}
