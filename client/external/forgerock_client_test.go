package external

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mmmorris1975/aws-runas/credentials"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var forgerockMock = httptest.NewServer(http.HandlerFunc(mockForgerockHandler))

func TestNewForgerockClient(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c, err := NewForgerockClient("https://localhost/auth/oauth2/realms/mock")
		if err != nil {
			t.Error(err)
			return
		}

		if c == nil {
			t.Error("nil client")
			return
		}

		if c.realm != "mock" {
			t.Error("bad realm")
			return
		}

		if c.baseUrl.String() != "https://localhost/auth" {
			t.Error("bad base url")
			return
		}
	})

	t.Run("bad url", func(t *testing.T) {
		if _, err := NewForgerockClient("ftp://localhost"); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("invalid realm", func(t *testing.T) {
		if _, err := NewForgerockClient("http://localhost/auth/json/mock"); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("invalid url", func(t *testing.T) {
		if _, err := NewForgerockClient("http://localhost/auth/realms/mock"); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestForgerockClient_Authenticate(t *testing.T) {
	t.Run("gather error", func(t *testing.T) {
		c := newMockForgerockClient()
		c.CredentialInputProvider = func(user, password string) (string, string, error) {
			return "", "", errors.New("an error")
		}

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestForgerockClient_Authenticate_Plain(t *testing.T) {
	t.Run("no mfa good", func(t *testing.T) {
		c := newMockForgerockClient()
		c.Username = "nomfa"
		c.Password = "goodPassword"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})

	t.Run("no mfa bad", func(t *testing.T) {
		c := newMockForgerockClient()
		c.CredentialInputProvider = func(u, p string) (string, string, error) {
			return "nomfa", "badPassword", nil
		}

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestForgerockClient_Authenticate_CodeMfa(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := newMockForgerockClient()
		c.Username = "codemfa"
		c.Password = "goodPassword"
		c.MfaTokenCode = "543210"
		c.MfaTokenProvider = func() (string, error) {
			return "54321", nil
		}

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})
}

func TestForgerockClient_Authenticate_PushMfa(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := newMockForgerockClient()
		c.Username = "pushmfa"
		c.Password = "goodPassword"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}

		t.Log("")
	})
}

func TestForgerockClient_Identity(t *testing.T) {
	t.Run("username set", func(t *testing.T) {
		c := &forgerockClient{baseClient: new(baseClient)}
		c.Username = "mockUser"

		id, err := c.Identity()
		if err != nil {
			t.Error(err)
			return
		}

		if id.Username != c.Username || id.IdentityType != "user" {
			t.Error("identity data mismatch")
		}

		if id.Provider != forgerockIdentityProvider || !strings.Contains(strings.ToLower(id.Provider), "forgerock") {
			t.Error("invalid identity provider")
		}
	})

	t.Run("username unset", func(t *testing.T) {
		c := &forgerockClient{baseClient: new(baseClient)}
		c.CredentialInputProvider = func(user, password string) (string, string, error) {
			return "aUser", "", nil
		}

		id, err := c.Identity()
		if err != nil {
			t.Error(err)
			return
		}

		if id.Username != "aUser" || id.IdentityType != "user" {
			t.Error("identity data mismatch")
		}

		if id.Provider != forgerockIdentityProvider || !strings.Contains(strings.ToLower(id.Provider), "forgerock") {
			t.Error("invalid identity provider")
		}
	})
}

func TestForgerockClient_IdentityToken(t *testing.T) {
	c := newMockForgerockClient()
	c.authUrl.Path = fmt.Sprintf("/base/oauth2/realms/%s", c.realm)
	c.ClientId = "12345"
	c.RedirectUri = "http://localhost:99999/"
	c.Scopes = []string{"profile", "group"} // just here for some cheap coverage wins

	token, err := c.IdentityToken()
	if err != nil {
		t.Error(err)
		return
	}

	if len(token.String()) < 50 || len(strings.Split(token.String(), `.`)) != 3 {
		t.Error("invalid identity token")
	}
}

func TestForgerockClient_SamlAssertion(t *testing.T) {
	c := newMockForgerockClient()
	c.authUrl.Path = fmt.Sprintf("/base/json/realms/%s", c.realm)
	_ = c.parseBaseUrl()

	saml, err := c.SamlAssertion()
	if err != nil {
		t.Error(err)
		return
	}

	if len(*saml) < 500 || c.saml == nil || len(*c.saml) != len(*saml) {
		t.Error("invalid saml assertion")
		return
	}

	t.Run("saml role details", func(t *testing.T) {
		rd, err := c.saml.RoleDetails()
		if err != nil {
			t.Error(err)
			return
		}

		if len(rd.Roles()) < 1 {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("saml roles", func(t *testing.T) {
		r, err := c.Roles()
		if err != nil {
			t.Error(err)
			return
		}

		if r == nil || len(*r) < 1 {
			t.Error("data mismatch")
			return
		}
	})
}

func newMockForgerockClient() *forgerockClient {
	c := &forgerockClient{baseClient: new(baseClient)}
	c.authUrl, _ = url.Parse(forgerockMock.URL)
	c.authUrl.Path = "/json/"

	c.httpClient = forgerockMock.Client()
	c.realm = "mockRealm"
	_ = c.parseBaseUrl()
	return c
}

func mockForgerockHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	switch p := r.URL.Path; {
	case strings.HasSuffix(p, "/authenticate"):
		// user authentication
		uHeader := r.Header.Get("X-OpenAM-Username")
		pHeader := r.Header.Get("X-OpenAM-Password")
		if len(uHeader) > 0 && len(pHeader) > 0 {
			// initial authentication attempt
			decodeAuthHeader := func(h string) string {
				parts := strings.Split(h, `?`)
				v, _ := base64.StdEncoding.DecodeString(parts[3])
				return string(v)
			}

			username := decodeAuthHeader(r.Header.Get("X-OpenAM-Username"))
			password := decodeAuthHeader(r.Header.Get("X-OpenAM-Password"))

			if password == "goodPassword" {
				if len(r.FormValue("authIndexValue")) > 0 {
					if username == "pushmfa" || username == "codemfa" {
						// return initial mfa prompt form
						reply := new(frMfaPrompt)
						reply.AuthId = username

						if username == "codemfa" {
							reply.Callbacks = []*frCallback{
								{
									Type: "PasswordCallback",
									Input: []map[string]interface{}{
										{"name": "IDToken1", "value": ""},
									},
								},
							}
						}

						j, _ := json.Marshal(reply)
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write(j)
						return
					}
				} else if username == "nomfa" {
					_, _ = w.Write([]byte("success"))
					return
				}
			}

			// return invalid username/password
			reply := &frApiError{
				Code:    http.StatusUnauthorized,
				Message: "invalid username or password",
			}
			j, _ := json.Marshal(reply)

			w.Header().Set("Content-Type", "application/json")
			http.Error(w, string(j), http.StatusUnauthorized)
			return
		}

		body, _ := ioutil.ReadAll(r.Body)

		form := new(frMfaPrompt)
		if err := json.Unmarshal(body, form); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}

		switch form.AuthId {
		case "pushmfa":
			if time.Now().Second()%10 == 0 {
				reply := &frApiError{
					Code:    http.StatusBadRequest,
					Message: "push mfa complete",
				}

				j, _ := json.Marshal(reply)
				http.Error(w, string(j), http.StatusBadRequest)
				return
			}

			j, _ := json.Marshal(form)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(j)
			return
		case "codemfa":
			mfa := new(frMfaPrompt)
			_ = json.Unmarshal(body, mfa)

			for _, cb := range mfa.Callbacks {
				if cb.Type == "PasswordCallback" {
					for _, x := range cb.Input {
						if x["name"] == "IDToken1" && x["value"] == "54321" {
							_, _ = w.Write([]byte("success"))
							return
						}
					}
				}
			}

			// return failure
			reply := &frApiError{
				Code:    http.StatusUnauthorized,
				Message: "invalid mfa code",
			}
			j, _ := json.Marshal(reply)
			http.Error(w, string(j), reply.Code)
			return
		default:
			reply := &frApiError{
				Code:    http.StatusUnauthorized,
				Message: "unsupported mfa type",
			}
			j, _ := json.Marshal(reply)
			http.Error(w, string(j), reply.Code)
			return
		}
	case strings.HasSuffix(p, "/authorize"):
		// Oauth authorization URL
		reqQ := r.URL.Query()

		newQ := url.Values{}
		newQ.Set("state", reqQ.Get("state"))
		newQ.Set("code", "mockAuthorizationCode")

		redirUri := fmt.Sprintf("%s?%s", reqQ.Get("redirect_uri"), newQ.Encode())
		w.Header().Set("Location", redirUri)
		http.Error(w, "", http.StatusFound)
	case strings.HasSuffix(p, "/access_token"):
		// Oauth token URL
		id := credentials.OidcIdentityToken("my.mockIdentityToken.WithSomeExtraStuffRequiredToPassTheTest")
		token := &oauthToken{
			AccessToken: "mockAccessToken",
			ExpiresIn:   3600,
			IdToken:     &id,
			Scope:       "openid",
			TokenType:   "bearer",
		}
		body, _ := json.Marshal(token)

		w.Header().Set("Content-Type", "application-json")
		_, _ = w.Write(body)
	case strings.HasSuffix(p, "/idpssoinit"):
		// SAML assertion fetching URL
		//nolint:lll
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
		_, _ = w.Write([]byte(body))
	default:
		http.NotFound(w, r)
	}
}
