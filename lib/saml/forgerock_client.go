package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	*baseAwsClient
	realm string
}

// NewForgerockSamlClient creates a Forgerock aware SAML client using information supplied by the provided metadata URL
func NewForgerockSamlClient(authUrl string) (*forgerockSamlClient, error) {
	bsc, err := newBaseAwsClient(authUrl)
	if err != nil {
		return nil, err
	}
	bsc.MfaType = MfaTypeAuto

	c := forgerockSamlClient{baseAwsClient: bsc}
	c.parseBaseUrl()
	c.parseRealm()

	return &c, nil
}

func (c *forgerockSamlClient) parseBaseUrl() {
	s := strings.Split(c.authUrl.String(), "/json/")
	u, _ := url.Parse(s[0])
	c.baseUrl = u
}

func (c *forgerockSamlClient) parseRealm() {
	p := strings.Split(c.authUrl.Path, "/realms/")
	r := strings.Split(p[1], "/")
	c.realm = r[0]
}

// Authenticate handles authentication against a Forgerock compatible identity provider
func (c *forgerockSamlClient) Authenticate() error {
	if err := c.gatherCredentials(); err != nil {
		return err
	}

	return c.auth()
}

// AwsSaml performs a SAML request using the well known AWS service provider URN.  The result of this request is cached
// in memory to avoid repeated requests to the Forgerock endpoint.
func (c *forgerockSamlClient) AwsSaml() (string, error) {
	if len(c.rawSamlResponse) > 0 {
		return c.rawSamlResponse, nil
	}

	u, err := url.Parse(fmt.Sprintf("%s/idpssoinit?metaAlias=%s&spEntityID=%s", c.baseUrl, c.realm, AwsUrn))
	if err != nil {
		return "", err
	}

	if err := c.samlRequest(u); err != nil {
		return "", err
	}

	return c.rawSamlResponse, nil
}

// REF: https://backstage.forgerock.com/docs/am/6.5/authorization-guide/index.html#sec-rest-authentication
func (c *forgerockSamlClient) auth() error {
	//u := fmt.Sprintf("%s/json/realms%s/authenticate", c.baseUrl, c.realm)
	u := c.authUrl.String()

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
				return new(errMfaNotConfigured)
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
