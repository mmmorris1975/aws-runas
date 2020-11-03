package external

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mmmorris1975/aws-runas/credentials"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var keycloakMock = httptest.NewServer(http.HandlerFunc(mockKeycloakHandler))

func TestNewKeycloakClient(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c, err := NewKeycloakClient("https://localhost")
		if err != nil {
			t.Error(err)
			return
		}

		if c == nil {
			t.Error("nil client")
			return
		}
	})

	t.Run("bad url", func(t *testing.T) {
		if _, err := NewKeycloakClient("ftp://localhost"); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestKeycloakClient_Authenticate(t *testing.T) {
	t.Run("bad gather creds", func(t *testing.T) {
		c := newMockKeycloakClient()
		c.CredentialInputProvider = func(user, password string) (string, string, error) {
			return "", "", errors.New("error")
		}

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("no mfa configured", func(t *testing.T) {
		c := newMockKeycloakClient()
		c.Username = "codemfa"
		c.Password = "goodPassword"

		c.httpClient = new(http.Client)
		c.setHttpClient()

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("mfa input error", func(t *testing.T) {
		c := newMockKeycloakClient()
		c.Username = "codemfa"
		c.Password = "goodPassword"
		c.MfaTokenProvider = func() (string, error) {
			return "", errors.New("error time")
		}

		c.httpClient = new(http.Client)
		c.setHttpClient()

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestKeycloakClient_Authenticate_Saml(t *testing.T) {
	samlPath := "/realms/test/protocol/saml/clients/aws"

	t.Run("bad creds", func(t *testing.T) {
		c := newMockKeycloakClient()
		c.authUrl.Path = samlPath
		c.CredentialInputProvider = func(user, password string) (string, string, error) {
			return "nomfa", "badPassword", nil
		}

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("no mfa", func(t *testing.T) {
		c := newMockKeycloakClient()
		c.authUrl.Path = samlPath
		c.Username = "nomfa"
		c.Password = "goodPassword"

		// must use a distinct http.Client for successful auth tests, to avoid seeing cookies from other tests
		c.httpClient = new(http.Client)
		c.setHttpClient()

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})

	t.Run("code mfa", func(t *testing.T) {
		c := newMockKeycloakClient()
		c.authUrl.Path = samlPath
		c.Username = "codemfa"
		c.Password = "goodPassword"
		c.MfaTokenCode = "543210"
		c.MfaTokenProvider = func() (string, error) {
			return "54321", nil
		}

		// must use a distinct http.Client for successful auth tests, to avoid seeing cookies from other tests
		c.httpClient = new(http.Client)
		c.setHttpClient()

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})
}

func TestKeycloakClient_Authenticate_Oidc(t *testing.T) {
	t.Run("bad creds", func(t *testing.T) {
		c := newMockKeycloakClient()
		c.CredentialInputProvider = func(user, password string) (string, string, error) {
			return "codemfa", "badPassword", nil
		}

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("no mfa", func(t *testing.T) {
		c := newMockKeycloakClient()
		c.Username = "nomfa"
		c.Password = "goodPassword"

		// must use a distinct http.Client for successful auth tests, to avoid seeing cookies from other tests
		c.httpClient = new(http.Client)
		c.setHttpClient()

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})

	t.Run("code mfa", func(t *testing.T) {
		c := newMockKeycloakClient()
		c.Username = "codemfa"
		c.Password = "goodPassword"
		c.MfaTokenCode = "543210"
		c.MfaTokenProvider = func() (string, error) {
			return "54321", nil
		}

		// must use a distinct http.Client for successful auth tests, to avoid seeing cookies from other tests
		c.httpClient = new(http.Client)
		c.setHttpClient()

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})
}

func TestKeycloakClient_Identity(t *testing.T) {
	t.Run("username set", func(t *testing.T) {
		c := &keycloakClient{baseClient: new(baseClient)}
		c.Username = "mockUser"

		id, err := c.Identity()
		if err != nil {
			t.Error(err)
			return
		}

		if id.Username != c.Username || id.IdentityType != "user" {
			t.Error("identity data mismatch")
		}

		if id.Provider != keycloakIdentityProvider || !strings.Contains(strings.ToLower(id.Provider), "keycloak") {
			t.Error("invalid identity provider")
		}
	})

	t.Run("username unset", func(t *testing.T) {
		c := &keycloakClient{baseClient: new(baseClient)}
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

		if id.Provider != keycloakIdentityProvider || !strings.Contains(strings.ToLower(id.Provider), "keycloak") {
			t.Error("invalid identity provider")
		}
	})
}

func TestKeycloakClient_IdentityToken(t *testing.T) {
	t.Run("pre-authenticated", func(t *testing.T) {
		c := newMockKeycloakClient()
		c.ClientId = "12345"
		c.RedirectUri = "http://localhost:99999/"
		c.Scopes = []string{"profile", "group"} // just here for some cheap coverage wins

		c.setHttpClient()
		c.httpClient.Jar.SetCookies(c.authUrl, []*http.Cookie{{
			Name:  "KEYCLOAK_SESSION",
			Value: "logged-in",
		}})

		token, err := c.IdentityToken()
		if err != nil {
			t.Error(err)
			return
		}

		if len(token.String()) < 50 || len(strings.Split(token.String(), `.`)) != 3 {
			t.Error("invalid identity token")
		}
	})

	t.Run("bad gather credentials", func(t *testing.T) {
		c := newMockKeycloakClient()
		c.httpClient = new(http.Client)
		c.CredentialInputProvider = func(user, password string) (string, string, error) {
			return "", "", errors.New("error time")
		}

		if _, err := c.IdentityToken(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestKeycloakClient_SamlAssertion(t *testing.T) {
	t.Run("invalid saml", func(t *testing.T) {
		c := newMockKeycloakClient()
		rawSaml := credentials.SamlAssertion("invalid saml")
		c.saml = &rawSaml

		if _, err := c.SamlAssertion(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("bad gather credentials", func(t *testing.T) {
		c := newMockKeycloakClient()
		c.httpClient = new(http.Client)
		c.CredentialInputProvider = func(user, password string) (string, string, error) {
			return "", "", errors.New("error time")
		}

		if _, err := c.SamlAssertion(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("pre-authenticated", func(t *testing.T) {
		c := newMockKeycloakClient()
		c.authUrl.Path = "/realms/test/protocol/saml/clients/aws"

		c.setHttpClient()
		c.httpClient.Jar.SetCookies(c.authUrl, []*http.Cookie{{
			Name:  "KEYCLOAK_SESSION",
			Value: "logged-in",
		}})

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
	})
}

func newMockKeycloakClient() *keycloakClient {
	c := &keycloakClient{baseClient: new(baseClient)}
	c.authUrl, _ = url.Parse(keycloakMock.URL)
	c.httpClient = keycloakMock.Client()
	return c
}

func mockKeycloakHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	switch p := r.URL.Path; {
	case strings.HasSuffix(p, "/openid-connect/auth"):
		// Oauth authorization URL
		// this url participates in the user authentication flow, so we'll need to distinguish between a user who is logged in and one that isn't
		// 200 status sends login form (like the SAML ep does)
		// 302 is the authorization token
		_, err := r.Cookie("KEYCLOAK_SESSION")
		if err == nil {
			// authenticated, send token
			reqQ := r.URL.Query()

			newQ := url.Values{}
			newQ.Set("state", reqQ.Get("state"))
			newQ.Set("code", "mockAuthorizationCode")

			redirUri := fmt.Sprintf("%s?%s", reqQ.Get("redirect_uri"), newQ.Encode())
			w.Header().Set("Location", redirUri)
			http.Error(w, "", http.StatusFound)
		}

		// unauthenticated, return login form
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, loginForm, r.Host)
	case strings.HasSuffix(p, "/openid-connect/token"):
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
	case strings.Contains(p, "/protocol/saml/clients/"):
		// SAML assertion fetching URL
		// this url participates in the user authentication flow, so we'll need to distinguish between a user who is logged in and one that isn't
		var body string
		_, err := r.Cookie("KEYCLOAK_SESSION")
		if err == nil {
			body = `
<html>
<head></head>
<body>
  <form method="post" action="http://%s/auth/realms/master/login-actions/authenticate">
    <input type="hidden" name="SAMLResponse" value="PHNhbWw6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlU2Vzc2lvbk5hbWUiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+bXktc2FtbC11c2VyPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHBzOi8vYXdzLmFtYXpvbi5jb20vU0FNTC9BdHRyaWJ1dGVzL1Nlc3Npb25EdXJhdGlvbiI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj40MzIwMDwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJ1cm46b2lkOjEuMy42LjEuNC4xLjU5MjMuMS4xLjEuMTEiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+Mjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoxMjM0NTY3ODkwOnJvbGUvUG93ZXJVc2VyLGFybjphd3M6aWFtOjoxMjM0NTY3ODkwOnNhbWwtcHJvdmlkZXIvbXlTU088L3NhbWw6QXR0cmlidXRlVmFsdWU+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5hcm46YXdzOmlhbTo6MDk4NzY1NDMyMTpyb2xlL1Bvd2VyVXNlcixhcm46YXdzOmlhbTo6MDk4NzY1NDMyMTpzYW1sLXByb3ZpZGVyL215U1NPPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YXJuOmF3czppYW06OjExMTExMTExMTpyb2xlL0FkbWluLGFybjphd3M6aWFtOjoxMTExMTExMTE6c2FtbC1wcm92aWRlci9teVNTTzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoyMjIyMjIyMjI6cm9sZS9tYW5hZ2VkLXJvbGUvQWRtaW4sYXJuOmF3czppYW06OjIyMjIyMjIyMjpzYW1sLXByb3ZpZGVyL215U1NPPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YXJuOmF3czppYW06OjMzMzMzMzMzMzpyb2xlL0FkbWluLGFybjphd3M6aWFtOjozMzMzMzMzMzM6c2FtbC1wcm92aWRlci9teVNTTzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+Cg=="/>
  </form>
</body>
</html>
`
		} else {
			body = loginForm
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, body, r.Host)
	case strings.Contains(p, "/login-actions/authenticate"):
		// login form handler
		cookie := &http.Cookie{Name: "KEYCLOAK_SESSION", Value: "authenticated", Secure: false, Path: "/"}

		if r.PostFormValue("password") == "goodPassword" {
			switch r.PostFormValue("username") {
			case "nomfa":
				http.SetCookie(w, cookie)
				_, _ = w.Write(nil)
				return
			case "codemfa":
				w.Header().Set("Content-Type", "text/html")
				_, _ = fmt.Fprintf(w, mfaForm, r.Host)
				return
			default:
				http.Error(w, "invalid username or password", http.StatusUnauthorized)
				return
			}
		}

		mfaData := r.PostFormValue("otp")
		if len(mfaData) > 0 {
			if mfaData == "54321" {
				http.SetCookie(w, cookie)
				_, _ = w.Write(nil)
				return
			}
			// invalid mfa code re-returns the form w/ http 200
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprintf(w, mfaForm, r.Host)
			return
		}

		http.Error(w, "invalid request", http.StatusBadRequest)
	default:
		http.NotFound(w, r)
	}
}

var loginForm = `
<html>
<head></head>
<body>
 <form method="post" action="http://%s/auth/realms/master/login-actions/authenticate">
  <input name="username" value=""  type="text" />
  <input name="password" type="password" />
  <input type="hidden" id="id-hidden-input" name="credentialId" />
 </form>
</body>
</html>
`

var mfaForm = `
<html>
<head></head>
<body>
 <form method="post" action="http://%s/auth/realms/master/login-actions/authenticate">
  <input name="otp" id="otp" value=""  type="text" />
 </form>
</body>
</html>
`
