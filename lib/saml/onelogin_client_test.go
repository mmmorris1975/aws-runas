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
	"time"
)

const olAppId = "54321"

func TestNewOneLoginSamlClient(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockOneloginHandler))
	defer s.Close()

	baseAuthUrl := fmt.Sprintf("%s/trust/saml2/launch/%s", s.URL, olAppId)

	t.Run("good", func(t *testing.T) {
		c, err := NewOneLoginSamlClient(fmt.Sprintf("%s?token=YWJjOjEyMw==", baseAuthUrl))
		if err != nil {
			t.Error(err)
			return
		}

		if len(c.appId) < 1 || c.subdomain != "127" || c.apiClientId != "abc" || c.apiClientSecret != "123" {
			t.Error("data mismatch")
		}
	})

	t.Run("missing token", func(t *testing.T) {
		_, err := NewOneLoginSamlClient(baseAuthUrl)
		if err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		_, err := NewOneLoginSamlClient(fmt.Sprintf("%s?token=cXFxcQ==", baseAuthUrl))
		if err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestOneloginSamlClient_AwsSaml(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockOneloginHandler))
	defer s.Close()

	c := newOneloginClient(s)

	if _, err := c.AwsSaml(); err != nil {
		t.Error(err)
		return
	}

	if len(c.rawSamlResponse) < 1 || len(c.decodedSaml) < 1 {
		t.Error("invalid SAML response")
		return
	}

	t.Run("GetIdentity", func(t *testing.T) {
		id, err := c.GetIdentity()
		if err != nil {
			t.Error(err)
			return
		}

		if id.IdentityType != "user" || id.Provider != IdentityProviderSaml || id.Username != "my-saml-user" {
			t.Error("data mismatch")
		}
	})

	t.Run("SessionDuration", func(t *testing.T) {
		d, err := c.GetSessionDuration()
		if err != nil {
			t.Error(err)
			return
		}

		if d != 43200 {
			t.Error("data mismatch")
		}
	})

	t.Run("Roles", func(t *testing.T) {
		r, err := c.Roles()
		if err != nil {
			t.Error(err)
			return
		}

		if r == nil || len(r) < 3 {
			t.Error("data mismatch")
		}
	})

	t.Run("populated saml", func(t *testing.T) {
		o := newOneloginClient(s)
		o.rawSamlResponse = "abc123"

		if _, err := o.AwsSaml(); err != nil {
			t.Error(err)
			return
		}

		if o.rawSamlResponse != "abc123" || len(o.decodedSaml) > 0 {
			t.Error("data mismatch")
		}
	})
}

func TestOneloginSamlClient_AuthenticateNoMfa(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockOneloginHandler))
	defer s.Close()

	c := newOneloginClient(s)
	c.apiToken = &oneloginApiToken{AccessToken: "tok123", TokenType: "bearer"}
	c.apiBaseUrl = s.URL

	t.Run("good", func(t *testing.T) {
		c.Username = "good"
		c.Password = "good"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("bad", func(t *testing.T) {
		c.Username = "not-good"
		c.Password = "bad"

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestOneloginSamlClient_AuthenticateTotpMfa(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockOneloginHandler))
	defer s.Close()

	c := newOneloginClient(s)
	c.apiToken = &oneloginApiToken{AccessToken: "tok123", TokenType: "bearer"}
	c.apiBaseUrl = s.URL
	c.Username = "codemfa"
	c.Password = "codemfa"

	t.Run("good", func(t *testing.T) {
		c.MfaToken = "123456"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("retry", func(t *testing.T) {
		c.MfaToken = "654321"
		c.MfaTokenProvider = func() (s string, e error) {
			return "123456", nil
		}

		if err := c.Authenticate(); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("no mfa", func(t *testing.T) {
		c.MfaToken = ""
		c.MfaTokenProvider = nil

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestOneloginSamlClient_AuthenticateNPushMfa(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockOneloginHandler))
	defer s.Close()

	c := newOneloginClient(s)
	c.apiToken = &oneloginApiToken{AccessToken: "tok123", TokenType: "bearer"}
	c.apiBaseUrl = s.URL
	c.Username = "pushmfa"
	c.Password = "pushmfa"

	if err := c.Authenticate(); err != nil {
		t.Error(err)
		return
	}
}

func newOneloginClient(s *httptest.Server) *oneloginSamlClient {
	u, _ := url.Parse(fmt.Sprintf("%s/trust/saml2/launch/%s", s.URL, olAppId))

	c := oneloginSamlClient{
		BaseAwsClient: new(BaseAwsClient),
		appId:         olAppId,
		subdomain:     strings.Split(u.Host, ".")[0],
	}
	c.httpClient = s.Client()
	c.authUrl = u

	return &c
}

func mockOneloginHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	switch p := r.URL.Path; {
	case p == "/auth/oauth2/v2/token":
		// The API initial authentication endpoint
		t := oneloginApiToken{
			AccessToken: "abc-123",
			TokenType:   "bearer",
		}

		data, err := json.Marshal(&t)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	case p == "/api/1/login/auth":
		// User login endpoint
		data := make(map[string]string)

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err = json.Unmarshal(body, &data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		reply := new(oneloginAuthReplyV1)
		if data["username_or_email"] == "good" && data["password"] == "good" {
			reply.Status = &oneloginApiStatus{
				Code:    200,
				Error:   false,
				Message: "Success",
				Type:    "success",
			}

			reply.Data = []*oneloginAuthDataV1{
				&oneloginAuthDataV1{
					ExpiresAt:    time.Now().Add(1 * time.Hour).String(),
					SessionToken: "AllGoodInDaHood",
					Status:       "Authenticated",
					User: &oneloginUser{
						Id:        1000,
						FirstName: "Good",
						LastName:  "Guy",
						Username:  data["username_or_email"],
					},
				},
			}
		} else if data["username_or_email"] == "codemfa" {
			reply.Status = &oneloginApiStatus{
				Code:    200,
				Error:   false,
				Message: "MFA is required for this user",
				Type:    "success",
			}

			reply.Data = []*oneloginAuthDataV1{
				&oneloginAuthDataV1{
					User: &oneloginUser{
						Id:        1001,
						FirstName: "Code",
						LastName:  "Mfa",
						Username:  data["username_or_email"],
					},
					StateToken:  "StateOfConfusion",
					CallbackUrl: fmt.Sprintf("http://%s/api/1/login/verify_factor", r.Host),
					MfaDevices: []*oneloginMfaDevice{
						&oneloginMfaDevice{
							Id:   111,
							Type: "Google Authenticator",
						},
					},
				},
			}
		} else if data["username_or_email"] == "pushmfa" {
			reply.Status = &oneloginApiStatus{
				Code:    200,
				Error:   false,
				Message: "MFA is required for this user",
				Type:    "success",
			}

			reply.Data = []*oneloginAuthDataV1{
				&oneloginAuthDataV1{
					User: &oneloginUser{
						Id:        1002,
						FirstName: "Push",
						LastName:  "Mfa",
						Username:  data["username_or_email"],
					},
					StateToken:  "StateOfConfusion",
					CallbackUrl: fmt.Sprintf("http://%s/api/1/login/verify_factor", r.Host),
					MfaDevices: []*oneloginMfaDevice{
						&oneloginMfaDevice{
							Id:   222,
							Type: "OneLogin Protect",
						},
					},
				},
			}
		} else {
			http.Error(w, "Authentication Failed: Invalid user credentials", http.StatusUnauthorized)
			return
		}

		b, err := json.Marshal(&reply)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(b)
	case strings.HasPrefix(p, "/api/1/users/") && strings.HasSuffix(p, "/otp_devices"):
		reply := new(oneloginEnrolledFactorsV1)
		reply.Status = &oneloginApiStatus{
			Code:    200,
			Error:   false,
			Message: "Success",
			Type:    "success",
		}
		reply.Data = make(map[string][]*oneloginEnrolledFactors)

		if strings.Contains(p, "/1001/") {
			// totp MFA
			reply.Data["otp_devices"] = []*oneloginEnrolledFactors{{
				Id:      111,
				Type:    "Google Authenticator",
				Active:  true,
				Default: true,
			}}
		} else if strings.Contains(p, "/1002/") {
			// push MFA user
			reply.Data["otp_devices"] = []*oneloginEnrolledFactors{{
				Id:      111,
				Type:    "Google Authenticator",
				Active:  true,
				Default: false,
			},
				{
					Id:      222,
					Type:    "OneLogin Protect",
					Active:  true,
					Default: true,
				}}
		} else {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		body, _ := json.Marshal(&reply)
		w.Write(body)
	case p == "/api/1/login/verify_factor":
		data := new(oneloginVerifyFactorRequest)

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err = json.Unmarshal(body, &data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		reply := new(oneloginAuthReplyV1)
		reply.Status = &oneloginApiStatus{
			Code:    200,
			Error:   false,
			Message: "Success",
			Type:    "success",
		}

		switch data.DeviceId {
		case "111":
			if data.OtpToken != "123456" {
				reply.Status.Error = true
				reply.Status.Code = http.StatusUnauthorized
				reply.Status.Type = "Unauthorized"
				reply.Status.Message = "Failed authentication with this factor"

				body, _ = json.Marshal(&reply)

				http.Error(w, string(body), http.StatusUnauthorized)
				return
			}

			reply.Data = []*oneloginAuthDataV1{
				&oneloginAuthDataV1{
					ExpiresAt:    time.Now().Add(1 * time.Hour).String(),
					SessionToken: "AllGoodInDaHood",
					Status:       "Authenticated",
				},
			}
		case "222":
			if time.Now().Unix()%2 == 0 {
				reply.Data = []*oneloginAuthDataV1{
					&oneloginAuthDataV1{
						ExpiresAt:    time.Now().Add(1 * time.Hour).String(),
						SessionToken: "AllGoodInDaHood",
						Status:       "Authenticated",
					},
				}
			} else {
				reply.Status.Message = "Push notification sent. Authentication pending."
			}
		default:
			http.Error(w, "Unknown Device ID", http.StatusBadRequest)
			return
		}

		b, _ := json.Marshal(&reply)
		w.Write(b)
	case p == "/session_via_api_token":
		// Post login session token exchange
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		v, err := url.ParseQuery(string(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if v.Get("session_token") == "AllGoodInDaHood" {
			w.Write([]byte("OK"))
		}
	case p == fmt.Sprintf("/trust/saml2/launch/%s", olAppId):
		// SAML assertion fetching URL
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
		fmt.Fprintf(w, body, r.Host)
	default:
		http.NotFound(w, r)
	}
}
