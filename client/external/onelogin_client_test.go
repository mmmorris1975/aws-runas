package external

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/shared"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var oneloginMock *httptest.Server

//nolint:gochecknoinits // too lazy to figure out a better way
func init() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", olDefaultHandler)
	mux.HandleFunc("/auth/oauth2/v2/token", olAuthTokenHandler)
	mux.HandleFunc("/oidc/2/auth", olOauthAuthHandler)
	mux.HandleFunc("/oidc/2/token", olOauthTokenHandler)
	mux.HandleFunc("/trust/saml2/launch/", olSamlHandler)
	mux.HandleFunc("/session_via_api_token", olSessionHandler)
	mux.HandleFunc("/api/1/login/auth", olAuthHandler)
	mux.HandleFunc("/api/1/users/", olMfaDeviceHandler)
	mux.HandleFunc("/verify_mfa_local", olVerifyMfaHandler)

	oneloginMock = httptest.NewServer(mux)
}

func TestNewOneloginClient(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		qs := url.Values{}
		qs.Add("token", base64.URLEncoding.EncodeToString([]byte("mockClientId:mockClientSecret")))
		u := fmt.Sprintf("%s?%s", oneloginMock.URL, qs.Encode())

		c, err := NewOneloginClient(u)
		if err != nil {
			t.Error(err)
			return
		}

		if c.apiToken == nil || c.apiToken.TokenType != "bearer" {
			t.Error("invalid API token returned")
		}

		if len(c.authUrl.RawQuery) > 0 {
			t.Error("found query string with authUrl after initialization")
		}
	})

	t.Run("bad url", func(t *testing.T) {
		if _, err := NewOneloginClient("telnet://this.is.bad"); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("bad api auth", func(t *testing.T) {
		qs := url.Values{}
		qs.Add("token", base64.URLEncoding.EncodeToString([]byte("badClientId:badSecret")))
		u := fmt.Sprintf("%s?%s", oneloginMock.URL, qs.Encode())
		if _, err := NewOneloginClient(u); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("empty api auth", func(t *testing.T) {
		if _, err := NewOneloginClient(oneloginMock.URL); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestOneloginClient_Authenticate(t *testing.T) {
	t.Run("bad gather creds", func(t *testing.T) {
		c := newMockOneloginClient()
		c.CredentialInputProvider = func(user, password string) (string, string, error) {
			return "", "", errors.New("error time")
		}

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("bad session token", func(t *testing.T) {
		c := newMockOneloginClient()
		c.Username = "badtoken"
		c.Password = "goodPassword"

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestOneloginClient_Authenticate_Plain(t *testing.T) {
	t.Run("no mfa good", func(t *testing.T) {
		c := newMockOneloginClient()
		c.Username = "nomfa"
		c.Password = "goodPassword"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})

	t.Run("no mfa bad", func(t *testing.T) {
		c := newMockOneloginClient()
		c.CredentialInputProvider = func(u, p string) (string, string, error) {
			return "nomfa", "badPassword", nil
		}

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestOneloginClient_Authenticate_CodeMfa(t *testing.T) {
	t.Run("explicit configuration", func(t *testing.T) {
		c := newMockOneloginClient()
		c.Username = "codemfa"
		c.Password = "goodPassword"
		c.MfaType = "code"
		c.MfaTokenProvider = func() (string, error) {
			return "54321", nil
		}

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})

	t.Run("discovered factor", func(t *testing.T) {
		c := newMockOneloginClient()
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

	t.Run("no factor found", func(t *testing.T) {
		c := newMockOneloginClient()
		c.Username = "codemfa"
		c.Password = "goodPassword"
		c.MfaType = "none"

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestOneloginClient_Authenticate_PushMfa(t *testing.T) {
	t.Run("explicit configuration", func(t *testing.T) {
		c := newMockOneloginClient()
		c.Username = "pushmfa"
		c.Password = "goodPassword"
		c.MfaType = "push"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})

	t.Run("discovered factor", func(t *testing.T) {
		c := newMockOneloginClient()
		c.Username = "pushmfa"
		c.Password = "goodPassword"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})
}

func TestOneloginClient_Identity(t *testing.T) {
	t.Run("username set", func(t *testing.T) {
		c := &oneloginClient{baseClient: new(baseClient)}
		c.Username = "mockUser"

		id, err := c.Identity()
		if err != nil {
			t.Error(err)
			return
		}

		if id.Username != c.Username || id.IdentityType != "user" {
			t.Error("identity data mismatch")
		}

		if id.Provider != oneloginIdentityProvider || !strings.Contains(strings.ToLower(id.Provider), "onelogin") {
			t.Error("invalid identity provider")
		}
	})

	t.Run("username unset", func(t *testing.T) {
		c := &oneloginClient{baseClient: new(baseClient)}
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

		if id.Provider != oneloginIdentityProvider || !strings.Contains(strings.ToLower(id.Provider), "onelogin") {
			t.Error("invalid identity provider")
		}
	})
}

func TestOneloginClient_IdentityToken(t *testing.T) {
	c := newMockOneloginClient()
	c.authUrl.Path = "/oidc/2"
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

func TestOneloginClient_SamlAssertion(t *testing.T) {
	c := newMockOneloginClient()
	c.authUrl.Path = "/trust/saml2/launch/12345"

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

	t.Run("bad saml", func(t *testing.T) {
		c := newMockOneloginClient()
		saml := credentials.SamlAssertion("this isn't saml")
		c.saml = &saml

		if _, err := c.SamlAssertion(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func newMockOneloginClient() *oneloginClient {
	c := &oneloginClient{baseClient: new(baseClient)}
	c.authUrl, _ = url.Parse(oneloginMock.URL)
	c.httpClient = oneloginMock.Client()
	c.Logger = new(shared.DefaultLogger)
	c.subdomain = strings.Split(c.authUrl.Host, `.`)[0]
	c.setApiBaseUrl()

	c.apiToken = &oneloginApiToken{
		AccessToken: "access token",
		AccountId:   12345,
		TokenType:   "Bearer",
	}

	return c
}

func olDefaultHandler(w http.ResponseWriter, r *http.Request) {
	// Set the expected Onelogin cookie for use with the Client Factory test code
	defer r.Body.Close()

	http.SetCookie(w, &http.Cookie{
		Name:  "sub_session_onelogin.com",
		Value: "abc123",
	})
	http.NotFound(w, r)
}

func olAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
	// The API initial authentication endpoint
	defer r.Body.Close()

	w.Header().Set("Content-Type", "application-json")

	user, pass, ok := r.BasicAuth()
	if !ok || user != "mockClientId" || pass != "mockClientSecret" {
		e := oneloginApiError{
			Status: &oneloginApiStatus{
				Error:   true,
				Code:    401,
				Type:    "Unauthorized",
				Message: "Authentication Failure",
			},
		}

		body, _ := json.Marshal(e)
		http.Error(w, string(body), http.StatusUnauthorized)
		return
	}

	token := oneloginApiToken{
		AccessToken: "mockApiAccessToken",
		AccountId:   12345,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		ExpiresIn:   3600,
		TokenType:   "bearer",
	}
	body, _ := json.Marshal(token)
	_, _ = w.Write(body)
}

func olOauthAuthHandler(w http.ResponseWriter, r *http.Request) {
	// Oauth authorization URL
	defer r.Body.Close()

	reqQ := r.URL.Query()

	newQ := url.Values{}
	newQ.Set("state", reqQ.Get("state"))
	newQ.Set("code", "mockAuthorizationCode")

	redirUri := fmt.Sprintf("%s?%s", reqQ.Get("redirect_uri"), newQ.Encode())
	w.Header().Set("Location", redirUri)
	http.Error(w, "", http.StatusFound)
}

func olOauthTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Oauth token URL
	defer r.Body.Close()

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
}

func olSamlHandler(w http.ResponseWriter, r *http.Request) {
	// SAML assertion fetching URL
	defer r.Body.Close()
	//nolint:lll
	body := `
<html>
<head></head>
<body>
  <form method="post" action="http://%s/saml">
    <input type="hidden" name="SAMLResponse" value="PHNhbWw6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlU2Vzc2lvbk5hbWUiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+bXktc2FtbC11c2VyPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHBzOi8vYXdzLmFtYXpvbi5jb20vU0FNTC9BdHRyaWJ1dGVzL1Nlc3Npb25EdXJhdGlvbiI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj40MzIwMDwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJ1cm46b2lkOjEuMy42LjEuNC4xLjU5MjMuMS4xLjEuMTEiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+Mjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoxMjM0NTY3ODkwOnJvbGUvUG93ZXJVc2VyLGFybjphd3M6aWFtOjoxMjM0NTY3ODkwOnNhbWwtcHJvdmlkZXIvbXlTU088L3NhbWw6QXR0cmlidXRlVmFsdWU+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5hcm46YXdzOmlhbTo6MDk4NzY1NDMyMTpyb2xlL1Bvd2VyVXNlcixhcm46YXdzOmlhbTo6MDk4NzY1NDMyMTpzYW1sLXByb3ZpZGVyL215U1NPPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YXJuOmF3czppYW06OjExMTExMTExMTpyb2xlL0FkbWluLGFybjphd3M6aWFtOjoxMTExMTExMTE6c2FtbC1wcm92aWRlci9teVNTTzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoyMjIyMjIyMjI6cm9sZS9tYW5hZ2VkLXJvbGUvQWRtaW4sYXJuOmF3czppYW06OjIyMjIyMjIyMjpzYW1sLXByb3ZpZGVyL215U1NPPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YXJuOmF3czppYW06OjMzMzMzMzMzMzpyb2xlL0FkbWluLGFybjphd3M6aWFtOjozMzMzMzMzMzM6c2FtbC1wcm92aWRlci9teVNTTzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+Cg=="/>
  </form>
</body>
</html>
`
	_, _ = fmt.Fprintf(w, body, r.Host)
}

func olSessionHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	st := r.PostFormValue("session_token")
	if len(st) < 1 {
		http.Error(w, "invalid session token", http.StatusBadRequest)
	}
	_, _ = w.Write(nil)
}

func olAuthHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authParam := make(map[string]string)
	if err := json.Unmarshal(body, &authParam); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if authParam["password"] != "goodPassword" {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	switch authParam["username_or_email"] {
	case "badtoken":
		reply := &oneloginAuthReply{
			Status: &oneloginApiStatus{
				Error:   false,
				Code:    http.StatusOK,
				Message: "success",
			},
			Data: []*oneloginAuthData{
				{Status: "SUCCESS"},
			},
		}

		data, err := json.Marshal(reply)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
		return
	case "nomfa":
		reply := &oneloginAuthReply{
			Status: &oneloginApiStatus{
				Error:   false,
				Code:    http.StatusOK,
				Message: "success",
			},
			Data: []*oneloginAuthData{
				{
					Status:       "SUCCESS",
					SessionToken: "token",
				},
			},
		}

		data, err := json.Marshal(reply)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
		return
	case "codemfa":
		cbUrl := fmt.Sprintf("http://%s/verify_mfa_local", r.Host)
		reply := &oneloginAuthReply{
			Status: new(oneloginApiStatus),
			Data: []*oneloginAuthData{
				{
					Status:      "MFA_REQUIRED",
					StateToken:  "state token",
					CallbackUrl: cbUrl,
					Devices: []*oneloginMfaDevice{
						{
							DeviceType: "",
							DeviceId:   123,
						},
					},
					User: &oneloginUser{Id: 123},
				},
			},
		}

		data, err := json.Marshal(reply)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	case "pushmfa":
		cbUrl := fmt.Sprintf("http://%s/verify_mfa_local", r.Host)
		reply := &oneloginAuthReply{
			Status: new(oneloginApiStatus),
			Data: []*oneloginAuthData{
				{
					Status:      "MFA_REQUIRED",
					StateToken:  "state token",
					CallbackUrl: cbUrl,
					Devices: []*oneloginMfaDevice{
						{
							DeviceType: "",
							DeviceId:   321,
						},
					},
					User: &oneloginUser{Id: 321},
				},
			},
		}

		data, err := json.Marshal(reply)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	default:
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
}

func olMfaDeviceHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if strings.HasSuffix(r.URL.Path, "/otp_devices") {
		parts := strings.Split(r.URL.Path, `/`)
		switch parts[4] {
		case "123":
			// code mfa user
			reply := &oneloginEnrolledFactors{
				Status: &oneloginApiStatus{
					Error: false,
					Code:  http.StatusOK,
				},
				Data: map[string][]*oneloginMfaFactor{
					"otp_devices": {
						&oneloginMfaFactor{
							Id:           555,
							Type:         "Google Authenticator",
							Active:       true,
							Default:      true,
							NeedsTrigger: false,
							DisplayName:  "Google Authenticator",
						},
					},
				},
			}

			data, err := json.Marshal(reply)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
		case "321":
			// push mfa user
			reply := &oneloginEnrolledFactors{
				Status: &oneloginApiStatus{
					Error: false,
					Code:  http.StatusOK,
				},
				Data: map[string][]*oneloginMfaFactor{
					"otp_devices": {
						&oneloginMfaFactor{
							Id:           666,
							Type:         "OneLogin Protect",
							Active:       true,
							Default:      true,
							NeedsTrigger: true,
							DisplayName:  "OneLogin Protect",
						},
					},
				},
			}

			data, err := json.Marshal(reply)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
		default:
			http.Error(w, "invalid user", http.StatusBadRequest)
			return
		}
	}
}

func olVerifyMfaHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	verifyReq := new(oneloginVerifyFactorRequest)
	if err := json.Unmarshal(body, verifyReq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch r := verifyReq; {
	case r.DeviceId == "555":
		// code mfa
		if r.OtpToken == "54321" {
			reply := &oneloginAuthReply{
				Status: &oneloginApiStatus{
					Error:   false,
					Code:    http.StatusOK,
					Message: "success",
				},
				Data: []*oneloginAuthData{
					{
						Status:       "SUCCESS",
						SessionToken: "token",
					},
				},
			}

			data, err := json.Marshal(reply)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
			return
		}

		reply := &oneloginApiError{Status: &oneloginApiStatus{
			Error:   true,
			Code:    http.StatusUnauthorized,
			Message: "Failed authentication with this factor",
		}}
		msg, _ := json.Marshal(reply)

		w.Header().Set("Content-Type", "application/json")
		http.Error(w, string(msg), http.StatusUnauthorized)
		return
	case r.DeviceId == "666":
		// push mfa
		reply := new(oneloginAuthReply)
		reply.Status = &oneloginApiStatus{Error: false, Code: http.StatusOK}

		if time.Now().Second()%10 == 0 {
			reply.Status.Message = "success"
			reply.Data = []*oneloginAuthData{
				{SessionToken: "session token"},
			}
		} else {
			reply.Status.Message = "pending"
		}

		data, err := json.Marshal(reply)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
		return
	default:
		http.Error(w, "unknown mfa failure", http.StatusUnauthorized)
	}
}
