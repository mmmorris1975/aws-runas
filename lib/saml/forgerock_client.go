package saml

import (
	"aws-runas/lib/identity"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// please be constant ... please be constant ... please be constant
	frOathSvcName = "mfa_oath_authentication"
	frPushSvcName = "mfa_push_authentication"
)

type frMfaForm struct {
	AuthId    string       `json:"authId"`
	Stage     string       `json:"stage"`
	Header    string       `json:"header"`
	Callbacks []frCallback `json:"callbacks"`
}

type frCallback struct {
	Type   string                   `json:"type"`
	Input  []map[string]interface{} `json:"input"`
	Output []map[string]interface{} `json:"output"`
}

type forgerockSamlClient struct {
	*SamlClient
	realm             string
	metaAlias         string
	baseUrl           *url.URL
	mfaSvcName        string
	rawAwsSamlDoc     string
	decodedAwsSamlDoc string
}

// NewForgerockSamlClient creates a Forgerock aware SAML client using information supplied by the provided metadata URL
func NewForgerockSamlClient(mdUrl string) (*forgerockSamlClient, error) {
	bsc, err := NewSamlClient(mdUrl)
	if err != nil {
		return nil, err
	}
	bsc.MfaType = MfaTypeAuto

	b, err := findBaseUrl(bsc.ssoUrl)
	if err != nil {
		return nil, err
	}

	return &forgerockSamlClient{
		SamlClient: bsc,
		realm:      bsc.mdUrl.Query().Get("realm"),
		metaAlias:  findMetaAlias(bsc.ssoUrl),
		baseUrl:    b,
	}, nil
}

// Authenticate handles authentication against a Forgerock compatible identity provider
func (c *forgerockSamlClient) Authenticate() error {
	if err := c.GatherCredentials(); err != nil {
		return err
	}

	return c.auth()
}

// Saml performs a request to the Forgerock server's SAML endpoint for the requested Service Provider ID
func (c *forgerockSamlClient) Saml(spId string) (string, error) {
	u, err := url.Parse(fmt.Sprintf("%s/idpssoinit?metaAlias=%s&spEntityID=%s", c.baseUrl, c.metaAlias, spId))
	if err != nil {
		return "", err
	}

	doc, err := c.SamlRequest(u)
	if err != nil {
		return "", err
	}

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

	return inputs["SAMLResponse"], nil
}

// AwsSaml performs a SAML request using the well known AWS service provider URN.  The result of this request is cached
// in memory to avoid repeated requests to the Forgerock endpoint.
func (c *forgerockSamlClient) AwsSaml() (string, error) {
	if len(c.rawAwsSamlDoc) > 0 {
		return c.rawAwsSamlDoc, nil
	}

	s, err := c.Saml(AwsUrn)
	if err != nil {
		return "", err
	}
	c.rawAwsSamlDoc = s

	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	c.decodedAwsSamlDoc = string(b)

	return s, nil
}

// GetIdentity retrieves the RoleSessionName attribute from the data returned from AwsSaml()
func (c *forgerockSamlClient) GetIdentity() (*identity.Identity, error) {
	d, err := c.getDecodedAwsSamlDoc()
	if err != nil {
		return nil, err
	}

	return getAwsSamlIdentity(d)
}

// Roles retrieves the list of roles available to use user from the data returned from AwsSaml()
func (c *forgerockSamlClient) Roles(user ...string) (identity.Roles, error) {
	d, err := c.getDecodedAwsSamlDoc()
	if err != nil {
		return nil, err
	}

	return getAwsSamlRoles(d)
}

// GetSessionDuration retrieves the SessionDuration attribute from the data returned from AwsSaml()
func (c *forgerockSamlClient) GetSessionDuration() (int64, error) {
	d, err := c.getDecodedAwsSamlDoc()
	if err != nil {
		return -1, err
	}

	return getAwsSessionDuration(d)
}

func (c *forgerockSamlClient) getDecodedAwsSamlDoc() (string, error) {
	var err error

	d := c.decodedAwsSamlDoc
	if len(d) < 1 {
		d, err = c.AwsSaml()
		if err != nil {
			return "", err
		}
	}

	return c.decodedAwsSamlDoc, nil
}

// REF: https://backstage.forgerock.com/docs/am/6.5/authorization-guide/index.html#sec-rest-authentication
func (c *forgerockSamlClient) auth() error {
	u := fmt.Sprintf("%s/json/realms%s/authenticate", c.baseUrl, c.realm)

	switch c.MfaType {
	case MfaTypeNone:
		// no mfa ... require that someone explicitly requests no MFA, instead of this being the default case
		res, err := c.doAuth(u)
		if err != nil {
			return err
		}
		defer res.Body.Close()
	case MfaTypeCode:
		// explicit request for otp mfa, fail if unsuccessful
		return c.authOtpMfa(fmt.Sprintf("%s?authIndexType=service&authIndexValue=%s", u, frOathSvcName))
	case MfaTypePush:
		// explicit request for push mfa, fail if unsuccessful
		return c.authPushMfa(fmt.Sprintf("%s?authIndexType=service&authIndexValue=%s", u, frPushSvcName))
	default:
		// try push, if fail ... try code, if fail ... try no mfa?
		c.MfaType = MfaTypePush
		if err := c.auth(); err != nil {
			if err.Error() == "auth status code 401" {
				c.MfaType = MfaTypeCode
				if err := c.auth(); err != nil {
					if err.Error() == "auth status code 401" {
						// this may or may not be a good idea
						c.MfaType = MfaTypeNone
						return c.auth()
					}
					return err
				}
				return nil
			}
			return err
		}
	}

	// Forgerock auth token will get get carried along in the http.Client's cookie jar
	return nil
}

func (c *forgerockSamlClient) doAuth(u string) (*http.Response, error) {
	r, err := frAuthReq(u, http.NoBody)
	if err != nil {
		return nil, err
	}
	r.Header.Set("X-OpenAM-Username", rfc2047EncodeString(c.Username))
	r.Header.Set("X-OpenAM-Password", rfc2047EncodeString(c.Password))

	res, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, new(errAuthFailure).WithCode(res.StatusCode)
	}

	return res, err
}

// mimics the browser request flow for using token-based MFA
func (c *forgerockSamlClient) authOtpMfa(u string) error {
	for {
		res, err := c.doAuth(u)
		if err != nil {
			return err
		}

		if len(c.MfaToken) < 1 {
			if c.MfaTokenProvider != nil {
				t, err := c.MfaTokenProvider()
				if err != nil {
					return err
				}
				c.MfaToken = t
			} else {
				return fmt.Errorf("MFA token is empty, and no token provider configured")
			}
		}

		f, err := c.handleMfaForm(res.Body)
		if err != nil {
			return err
		}

		req, err := frAuthReq(u, bytes.NewReader(f))
		if err != nil {
			return err
		}

		res, err = c.httpClient.Do(req)
		if err != nil {
			return err
		}

		if res.StatusCode == http.StatusOK {
			break
		} else if res.StatusCode == http.StatusUnauthorized {
			c.MfaToken = ""
			fmt.Println("invalid mfa code ... try again")
		} else {
			return new(errMfaFailure).WithCode(res.StatusCode)
		}
	}

	return nil
}

func (c *forgerockSamlClient) authPushMfa(u string) error {
	res, err := c.doAuth(u)
	if err != nil {
		return err
	}

	b, err := c.handleMfaForm(res.Body)
	if err != nil {
		return err
	}

	fmt.Println("Waiting for Push MFA confirmation")
	for {
		time.Sleep(1250 * time.Millisecond)

		req, err := frAuthReq(u, bytes.NewReader(b))
		if err != nil {
			return err
		}

		res, err = c.httpClient.Do(req)
		if err != nil {
			return err
		}

		if res.StatusCode != http.StatusOK {
			if res.StatusCode == http.StatusBadRequest {
				// this is actually good, since we send data to the endpoint which wasn't the expected form,
				// that means it's probably the success message from the service saying MFA is done
				break
			}
			return new(errMfaFailure).WithCode(res.StatusCode)
		}

		b, err = c.handleMfaForm(res.Body)
		if err != nil {
			return err
		}
	}
	fmt.Println("Push MFA action confirmed")

	return nil
}

func (c *forgerockSamlClient) handleMfaForm(r io.ReadCloser) ([]byte, error) {
	defer r.Close()
	f := new(frMfaForm)

	d := json.NewDecoder(r)
	if err := d.Decode(f); err != nil {
		// invalid json format ... not json structure
		return nil, err
	}

	for _, e := range f.Callbacks {
		if e.Type == "PasswordCallback" {
			for _, x := range e.Input {
				if x["name"] == "IDToken1" {
					x["value"] = c.MfaToken
				}
			}
		}
	}

	j, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}

	return j, nil
}

// Perform RFC 2047 encoding to support full UTF8 names and passwords
// REF: https://backstage.forgerock.com/docs/am/6.5/authentication-guide/#sec-rest-authentication
func rfc2047EncodeString(s string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(s))
	return fmt.Sprintf("=?UTF-8?B?%s?=", enc)
}

func frAuthReq(u string, b io.Reader) (*http.Request, error) {
	r, err := http.NewRequest(http.MethodPost, u, b)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept-API-Version", "resource=2.0, protocol=1.0")

	return r, nil
}

func findMetaAlias(u *url.URL) string {
	var aliasIdx int
	parts := strings.Split(u.Path, `/`)

	for i, s := range parts {
		if strings.EqualFold(s, "metaAlias") {
			aliasIdx = i + 1
			break
		}
	}

	return fmt.Sprintf("/%s", strings.Join(parts[aliasIdx:], `/`))
}

func findBaseUrl(u *url.URL) (*url.URL, error) {
	var baseIdx int
	parts := strings.Split(u.Path, `/`)

	for i, s := range parts {
		if strings.EqualFold(s, "metaAlias") {
			baseIdx = i - 1
			break
		}
	}

	r, err := url.ParseRequestURI(strings.Join(parts[:baseIdx], `/`))
	if err != nil {
		return nil, err
	}

	return u.ResolveReference(r), nil
}
