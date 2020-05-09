package saml

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNewOktaSamlClient(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c, err := NewOktaSamlClient("https://example.okta.com/home/amazon_aws/0oo0987654321/111")
		if err != nil {
			t.Error(err)
			return
		}

		if c.httpClient.CheckRedirect != nil {
			t.Error("HTTP client CheckRedirect is not null")
			return
		}
	})

	t.Run("bad url", func(t *testing.T) {
		_, err := NewOktaSamlClient("not-a-url")
		if err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestOktaSamlClient_Authenticate(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockOktaHttpHandler))
	defer s.Close()

	c, err := newOktaClient(s)
	if err != nil {
		t.Error(err)
		return
	}

	t.Run("good", func(t *testing.T) {
		c.Username = "gooduser"
		c.Password = "agoodboi"
		c.MfaType = MfaTypeNone

		if err := c.Authenticate(); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("bad password", func(t *testing.T) {
		c.Username = "baduser"
		c.Password = "notmypassword"

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestOktaSamlClient_AuthenticateToken(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockOktaHttpHandler))
	defer s.Close()

	c, err := newOktaClient(s)
	if err != nil {
		t.Error(err)
		return
	}

	c.Username = "mfauser"
	c.Password = "tokenmfa"

	t.Run("mfa", func(t *testing.T) {
		c.MfaToken = "123456"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("mfa retry", func(t *testing.T) {
		c.MfaToken = "654321"
		c.MfaTokenProvider = func() (s string, e error) {
			return "123456", nil
		}

		if err := c.Authenticate(); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("no provider", func(t *testing.T) {
		c.MfaToken = ""
		c.MfaTokenProvider = nil

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestOktaSamlClient_AwsSaml(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockOktaHttpHandler))
	defer s.Close()

	c, err := newOktaClient(s)
	if err != nil {
		t.Error(err)
		return
	}

	if len(c.rawSamlResponse) > 0 || len(c.decodedSaml) > 0 {
		t.Error("found unexpected saml response")
		return
	}

	if _, err := c.AwsSaml(); err != nil {
		t.Error(err)
		return
	}

	t.Run("GetIdentity", func(t *testing.T) {
		id, err := c.GetIdentity()
		if err != nil {
			t.Error(err)
			return
		}

		if id.IdentityType != "user" || id.Provider != "SAMLIdentityProvider" || id.Username != "my-okta-user" {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("GetSessionDuration", func(t *testing.T) {
		d, err := c.GetSessionDuration()
		if err != nil {
			t.Error(err)
			return
		}

		if d != 43200 {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("Roles", func(t *testing.T) {
		r, err := c.Roles()
		if err != nil {
			t.Error(err)
			return
		}

		if len(r) < 4 {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("with saml", func(t *testing.T) {
		k, err := newOktaClient(s)
		if err != nil {
			t.Error(err)
			return
		}
		k.rawSamlResponse = "123456"

		if _, err := c.AwsSaml(); err != nil {
			t.Error(err)
			return
		}

		if k.rawSamlResponse != "123456" {
			t.Error("data mismatch")
		}
	})
}

func newOktaClient(s *httptest.Server) (*oktaSamlClient, error) {
	u, err := url.Parse(fmt.Sprintf("%s/home/amazon_aws/1234567890/abc", s.URL))
	if err != nil {
		return nil, err
	}

	c := &oktaSamlClient{BaseAwsClient: new(BaseAwsClient)}
	c.authUrl = u
	c.httpClient = s.Client()
	c.httpClient.CheckRedirect = nil

	return c, nil
}

func mockOktaHttpHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.URL.Path == "/api/v1/authn" {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		creds := make(map[string]string)
		if err := json.Unmarshal(body, &creds); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if creds["username"] == "gooduser" && creds["password"] == "agoodboi" {
			res := apiResponse{Status: "SUCCESS", SessionToken: "allG00D"}
			body, _ := json.Marshal(&res)
			w.Write(body)
			return
		} else if creds["username"] == "mfauser" {
			res := apiResponse{
				Status:     "MFA_REQUIRED",
				StateToken: "StateOfDelirium",
				Details: responseDetail{
					MfaFactors: nil,
				},
			}
			if creds["password"] == "tokenmfa" {
				vfyUrl := fmt.Sprintf("http://%s/api/v1/authn/factors/tokenmfa", r.Host)
				f := mfaFactor{
					Id:   "o0tokenmfa0o",
					Type: "token:software:totp",
					Links: map[string]interface{}{
						"verify": map[string]string{"href": vfyUrl},
					},
				}
				res.Details.MfaFactors = []*mfaFactor{&f}

				body, _ := json.Marshal(&res)
				w.Write(body)
				return
			} else {

			}
		} else {
			http.Error(w, `{"errorSummary": "Authentication failed"}`, http.StatusUnauthorized)
		}
	} else if strings.HasPrefix(r.URL.Path, "/api/v1/authn/factors/") {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if strings.HasSuffix(r.URL.Path, "tokenmfa") {
			res := new(mfaResponse)
			json.Unmarshal(body, &res)

			if res.Token == "StateOfDelirium" && res.Code == "123456" {
				s := apiResponse{Status: "SUCCESS", SessionToken: "MySession"}
				bytes, _ := json.Marshal(&s)
				w.Write(bytes)
				return
			} else {
				http.Error(w, `{"errorSummary": "Invalid Passcode/Answer"}`, http.StatusForbidden)
				return
			}
		}
	} else if strings.HasPrefix(r.URL.Path, "/home/amazon_aws/") {
		body := `
<html>
<head></head>
<body>
<form method="post">
<input type="hidden" name="SAMLResponse" value="PHNhbWwyOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YXJuOmF3czppYW06OjEyMzQ1Njc4OTAxMjM6c2FtbC1wcm92aWRlci9Pa3RhLGFybjphd3M6aWFtOjoxMjM0NTY3ODkwMTIzOnJvbGUvTXlGYWtlUm9sZTwvc2FtbDI6QXR0cmlidXRlVmFsdWU+PHNhbWwyOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YXJuOmF3czppYW06OjAxMjM0NTY3ODkwMTpzYW1sLXByb3ZpZGVyL09rdGEsYXJuOmF3czppYW06OjAxMjM0NTY3ODkwMTpyb2xlL0Zha2VidXN0ZWRSb2xlPC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48c2FtbDI6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5hcm46YXdzOmlhbTo6MTIzNDU2Nzg5MDEyOnNhbWwtcHJvdmlkZXIvT2t0YSxhcm46YXdzOmlhbTo6MTIzNDU2Nzg5MDEyOnJvbGUvQWRtaW48L3NhbWwyOkF0dHJpYnV0ZVZhbHVlPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoyMzQ1Njc4OTAxMjM6c2FtbC1wcm92aWRlci9Pa3RhLGFybjphd3M6aWFtOjoyMzQ1Njc4OTAxMjM6cm9sZS9BZG1pbjwvc2FtbDI6QXR0cmlidXRlVmFsdWU+PHNhbWwyOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlU2Vzc2lvbk5hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPm15LW9rdGEtdXNlcjwvc2FtbDI6QXR0cmlidXRlVmFsdWU+PC9zYW1sMjpBdHRyaWJ1dGU+PHNhbWwyOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9TZXNzaW9uRHVyYXRpb24iIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPjQzMjAwPC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48L3NhbWwyOkF0dHJpYnV0ZT48L3NhbWwyOkF0dHJpYnV0ZVN0YXRlbWVudD4K"/>
</form>
</body>
</html>
`
		fmt.Fprint(w, body)
	} else {
		http.NotFound(w, r)
	}
}
