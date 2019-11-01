package saml

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewForgerockSamlClient(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockHttpHandler))
	defer s.Close()

	t.Run("good", func(t *testing.T) {
		u := fmt.Sprintf(`%s/auth/saml2/jsp/exportmetadata.jsp?entityid=%s&realm=/mock-test`, s.URL, s.URL)

		c, err := NewForgerockSamlClient(u)
		if err != nil {
			t.Error(err)
			return
		}

		if c.entityId != s.URL || c.realm != "/mock-test" {
			t.Error("data mismatch")
		}
	})

	t.Run("bad url", func(t *testing.T) {
		_, err := NewForgerockSamlClient("not-a-url")
		if err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestForgerockSamlClient_AwsSaml(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockHttpHandler))
	defer s.Close()

	c, err := newClient(s)
	if err != nil {
		t.Error(err)
		return
	}

	t.Run("GetIdentity", func(t *testing.T) {
		id, err := c.GetIdentity()
		if err != nil {
			t.Error(err)
			return
		}

		if id.IdentityType != "user" || id.Provider != "SAMLClient" || id.Username != "my-saml-user" {
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

		if len(r) < 5 {
			t.Error("data mismatch")
			return
		}
	})
}

func TestForgerockSamlClient_AuthenticateNone(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockHttpHandler))
	defer s.Close()

	c, err := newClient(s)
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

func TestForgerockSamlClient_AuthenticateToken(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockHttpHandler))
	defer s.Close()

	c, err := newClient(s)
	if err != nil {
		t.Error(err)
		return
	}

	t.Run("mfa", func(t *testing.T) {
		c.Username = "mfauser"
		c.Password = "mfapassword"
		c.MfaType = MfaTypeCode
		c.MfaToken = "54321"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("mfa retry", func(t *testing.T) {
		c.Username = "mfauser"
		c.Password = "mfapassword"
		c.MfaType = MfaTypeCode
		c.MfaToken = "12345"
		c.MfaTokenProvider = func() (s string, e error) {
			return "54321", nil
		}

		if err := c.Authenticate(); err != nil {
			t.Error(err)
			return
		}
	})
}

func TestForgerockSamlClient_AuthenticatePush(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockHttpHandler))
	defer s.Close()

	c, err := newClient(s)
	if err != nil {
		t.Error(err)
		return
	}

	t.Run("push", func(t *testing.T) {
		c.Username = "pushuser"
		c.Password = "pushpassword"
		c.MfaType = MfaTypePush

		if err := c.Authenticate(); err != nil {
			t.Error(err)
			return
		}
	})
}

func newClient(s *httptest.Server) (*forgerockSamlClient, error) {
	base, err := url.Parse(s.URL + "/auth")
	if err != nil {
		return nil, err
	}

	c := &forgerockSamlClient{
		SamlClient: new(SamlClient),
		realm:      "/mock-test",
		metaAlias:  "someta",
		baseUrl:    base,
	}
	c.httpClient = s.Client()

	return c, nil
}

// httptest.NewServer(http.HandlerFunc(mockHttpHandler))
func mockHttpHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	q := r.URL.Query()
	frm := new(frMfaForm)

	if r.URL.Path == "/auth/json/realms/mock-test/authenticate" {
		user := decodeAuthHeader(r.Header.Get("X-OpenAM-Username"))
		pass := decodeAuthHeader(r.Header.Get("X-OpenAM-Password"))

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if len(body) > 0 {
			if err := json.Unmarshal(body, frm); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			for _, c := range frm.Callbacks {
				if c.Type == "PasswordCallback" {
					for _, i := range c.Input {
						if i["name"] == "IDToken1" && i["value"] == "54321" {
							return
						}
					}
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
				} else if c.Type == "ConfirmationCallback" {
					if time.Now().Unix()%5 == 0 {
						time.Sleep(200 * time.Millisecond)
						http.Error(w, `{"status": "success"}`, http.StatusBadRequest)
						return
					}

					b, _ := json.Marshal(frm)
					w.Write(b)
					return
				} else {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
				}
				return
			}
		}

		if user == "gooduser" && pass == "agoodboi" {
			return
		} else if user == "mfauser" && pass == "mfapassword" && q.Get("authIndexValue") == frOathSvcName {
			cb := frCallback{
				Type:  "PasswordCallback",
				Input: []map[string]interface{}{{"name": "IDToken1"}},
			}

			b, err := json.Marshal(&frMfaForm{Callbacks: []frCallback{cb}})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(b)
			return
		} else if user == "pushuser" && pass == "pushpassword" && q.Get("authIndexValue") == frPushSvcName {
			cb := frCallback{
				Type:  "ConfirmationCallback",
				Input: []map[string]interface{}{map[string]interface{}{"name": "WaitTime"}},
			}

			b, err := json.Marshal(&frMfaForm{Callbacks: []frCallback{cb}})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(b)
			return
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	} else if r.URL.Path == "/auth/saml2/jsp/exportmetadata.jsp" {
		e := q.Get("entityid")
		realm := q.Get("realm")

		body := fmt.Sprintf(`
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<EntityDescriptor entityID="%s" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://%s/auth/SSOPOST/metaAlias/%s/saml-idp"/>
  </IDPSSODescriptor>
</EntityDescriptor>
`, e, r.Host, realm)

		fmt.Fprint(w, body)
	} else if r.URL.Path == "/auth/idpssoinit" && q.Get("spEntityID") == AwsUrn {
		body := `
<html>
<head></head>
<body>
<form method="post">
<input type="hidden" name="SAMLResponse" value="PHNhbWw6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlU2Vzc2lvbk5hbWUiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+bXktc2FtbC11c2VyPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHBzOi8vYXdzLmFtYXpvbi5jb20vU0FNTC9BdHRyaWJ1dGVzL1Nlc3Npb25EdXJhdGlvbiI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj40MzIwMDwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJ1cm46b2lkOjEuMy42LjEuNC4xLjU5MjMuMS4xLjEuMTEiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+Mjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoxMjM0NTY3ODkwOnJvbGUvUG93ZXJVc2VyLGFybjphd3M6aWFtOjoxMjM0NTY3ODkwOnNhbWwtcHJvdmlkZXIvbXlTU088L3NhbWw6QXR0cmlidXRlVmFsdWU+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5hcm46YXdzOmlhbTo6MDk4NzY1NDMyMTpyb2xlL1Bvd2VyVXNlcixhcm46YXdzOmlhbTo6MDk4NzY1NDMyMTpzYW1sLXByb3ZpZGVyL215U1NPPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YXJuOmF3czppYW06OjExMTExMTExMTpyb2xlL0FkbWluLGFybjphd3M6aWFtOjoxMTExMTExMTE6c2FtbC1wcm92aWRlci9teVNTTzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoyMjIyMjIyMjI6cm9sZS9tYW5hZ2VkLXJvbGUvQWRtaW4sYXJuOmF3czppYW06OjIyMjIyMjIyMjpzYW1sLXByb3ZpZGVyL215U1NPPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YXJuOmF3czppYW06OjMzMzMzMzMzMzpyb2xlL0FkbWluLGFybjphd3M6aWFtOjozMzMzMzMzMzM6c2FtbC1wcm92aWRlci9teVNTTzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+Cg=="/>
</form>
</body>
</html>
`
		fmt.Fprint(w, body)
	} else {
		http.NotFound(w, r)
	}
}

func decodeAuthHeader(data string) string {
	sp := strings.Split(data, "?")
	if len(sp) < 4 {
		return ""
	}

	str, err := base64.StdEncoding.DecodeString(sp[3])
	if err != nil {
		return ""
	}

	return string(str)
}
