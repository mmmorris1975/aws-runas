/*
 * Copyright (c) 2021 Michael Morris. All Rights Reserved.
 *
 * Licensed under the MIT license (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * https://github.com/mmmorris1975/aws-runas/blob/master/LICENSE
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under the License.
 */

package external

import (
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
)

var oktaMock *httptest.Server

//nolint:gochecknoinits // too lazy to figure out a better way
func init() {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/authorize", oktaOauthAuthHandler)
	mux.HandleFunc("/v1/token", oktaOauthTokenHandler)
	mux.HandleFunc("/home/amazon_aws/", oktaSamlHandler)
	mux.HandleFunc("/api/v1/authn", oktaUserAuthHandler)
	mux.HandleFunc("/verify_mfa_local", oktaVerifyMfaHandler)

	oktaMock = httptest.NewServer(mux)
}

func TestNewOktaClient(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c, err := NewOktaClient("https://this.is.a.test")
		if err != nil {
			t.Error(err)
			return
		}

		if c == nil {
			t.Error("nil client")
			return
		}

		if c.authUrl == nil || c.httpClient == nil {
			t.Error("invalid client")
		}
	})

	t.Run("error", func(t *testing.T) {
		if _, err := NewOktaClient("gopher://this.is.bad"); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestOktaClient_Authenticate(t *testing.T) {
	t.Run("bad gather creds", func(t *testing.T) {
		c := newMockOktaClient()
		c.CredentialInputProvider = func(user, password string) (string, string, error) {
			return "", "", errors.New("error")
		}

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("bad factor", func(t *testing.T) {
		c := newMockOktaClient()
		c.Username = "yubikey"
		c.Password = "goodPassword"

		if err := c.Authenticate(); err == nil {
			t.Error(err)
		}
	})
}

func TestOktaClient_Authenticate_Plain(t *testing.T) {
	t.Run("no mfa good", func(t *testing.T) {
		c := newMockOktaClient()
		c.Username = "nomfa"
		c.Password = "goodPassword"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})

	t.Run("no mfa bad", func(t *testing.T) {
		c := newMockOktaClient()
		c.CredentialInputProvider = func(u, p string) (string, string, error) {
			return "nomfa", "badPassword", nil
		}

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("bad api status", func(t *testing.T) {
		c := newMockOktaClient()
		c.Username = "badstatus"
		c.Password = "goodPassword"

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestOktaClient_Authenticate_CodeMfa(t *testing.T) {
	t.Run("no factor found", func(t *testing.T) {
		c := newMockOktaClient()
		c.Username = "codemfa"
		c.Password = "goodPassword"

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("good", func(t *testing.T) {
		c := newMockOktaClient()
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

func TestOktaClient_Authenticate_PushMfa(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := newMockOktaClient()
		c.Username = "pushmfa"
		c.Password = "goodPassword"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}

		t.Log("")
	})
}

func TestOktaClient_Identity(t *testing.T) {
	t.Run("username set", func(t *testing.T) {
		c, err := NewOktaClient("https://this.is.a.test")
		if err != nil {
			t.Error(err)
			return
		}
		c.Username = "mockUser"

		id, err := c.Identity()
		if err != nil {
			t.Error(err)
			return
		}

		if id.Username != c.Username || id.IdentityType != "user" {
			t.Error("identity data mismatch")
		}

		if id.Provider != oktaIdentityProvider || !strings.Contains(strings.ToLower(id.Provider), "okta") {
			t.Error("invalid identity provider")
		}
	})

	t.Run("username unset", func(t *testing.T) {
		c, err := NewOktaClient("https://this.is.a.test")
		if err != nil {
			t.Error(err)
			return
		}
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

		if id.Provider != oktaIdentityProvider || !strings.Contains(strings.ToLower(id.Provider), "okta") {
			t.Error("invalid identity provider")
		}
	})
}

func TestOktaClient_IdentityToken(t *testing.T) {
	c := newMockOktaClient()
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

func TestOktaClient_SamlAssertion(t *testing.T) {
	c := newMockOktaClient()
	c.authUrl.Path = "/home/amazon_aws/part1/123"

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

func newMockOktaClient() *oktaClient {
	c := &oktaClient{
		baseClient:   new(baseClient),
		sessionToken: "mockSessionToken",
	}
	c.authUrl, _ = url.Parse(oktaMock.URL)
	c.httpClient = oktaMock.Client()
	c.Logger = new(shared.DefaultLogger)
	return c
}

func oktaOauthAuthHandler(w http.ResponseWriter, r *http.Request) {
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

func oktaOauthTokenHandler(w http.ResponseWriter, r *http.Request) {
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

func oktaSamlHandler(w http.ResponseWriter, r *http.Request) {
	// SAML assertion fetching URL
	defer r.Body.Close()
	//nolint:lll
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
	_, _ = w.Write([]byte(body))
}

func oktaUserAuthHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	creds := make(map[string]string)
	if err := json.Unmarshal(data, &creds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if creds["password"] == "goodPassword" {
		switch creds["username"] {
		case "badstatus":
			reply := oktaAuthnResponse{
				Status:       "unknown",
				SessionToken: "mock session token",
			}

			body, _ := json.Marshal(reply)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			return
		case "nomfa":
			reply := oktaAuthnResponse{
				Status:       "SUCCESS",
				SessionToken: "mock session token",
			}

			body, _ := json.Marshal(reply)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			return
		case "codemfa":
			reply := oktaAuthnResponse{
				Status:     "MFA_REQUIRED",
				StateToken: "mock state token",
				EmbeddedData: struct {
					MfaFactors []*oktaMfaFactor `json:"factors"`
				}{[]*oktaMfaFactor{
					{
						Id:         "12345",
						FactorType: "token:software:totp",
						Provider:   "Google Authenticator",
						Links: map[string]struct {
							Href string `json:"href"`
						}{"verify": {Href: fmt.Sprintf("http://%s/verify_mfa_local", r.Host)}},
					},
				}},
			}

			body, _ := json.Marshal(reply)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			return
		case "pushmfa":
			reply := oktaAuthnResponse{
				Status:     "MFA_REQUIRED",
				StateToken: "mock state token",
				EmbeddedData: struct {
					MfaFactors []*oktaMfaFactor `json:"factors"`
				}{[]*oktaMfaFactor{
					{
						Id:         "12345",
						FactorType: "token:software:totp",
						Provider:   "Google Authenticator",
						Links: map[string]struct {
							Href string `json:"href"`
						}{"verify": {Href: fmt.Sprintf("http://%s/verify_mfa_local", r.Host)}},
					},
					{
						Id:         "54321",
						FactorType: "push",
						Provider:   "Okta Verify",
						Links: map[string]struct {
							Href string `json:"href"`
						}{"verify": {Href: fmt.Sprintf("http://%s/verify_mfa_local", r.Host)}},
					},
				}},
			}

			body, _ := json.Marshal(reply)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			return
		case "yubikey":
			reply := oktaAuthnResponse{
				Status:     "MFA_REQUIRED",
				StateToken: "mock state token",
				EmbeddedData: struct {
					MfaFactors []*oktaMfaFactor `json:"factors"`
				}{[]*oktaMfaFactor{
					{
						Id:         "12345",
						FactorType: "Yubikey",
						Provider:   "yubikey",
						Links: map[string]struct {
							Href string `json:"href"`
						}{"verify": {Href: fmt.Sprintf("http://%s/verify_mfa_local", r.Host)}},
					},
				}},
			}

			body, _ := json.Marshal(reply)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			return
		}
	}

	reply := oktaApiError{
		Code:    "401 Unauthorized",
		Message: "Invalid credentials",
		Id:      "mock",
	}
	j, _ := json.Marshal(reply)
	w.Header().Set("Content-Type", "application/json")
	http.Error(w, string(j), http.StatusUnauthorized)
}

func oktaVerifyMfaHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	mfa := new(oktaMfaResponse)
	if err := json.Unmarshal(body, mfa); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(mfa.Code) > 0 {
		// code mfa
		if mfa.Code == "54321" {
			reply := &oktaAuthnResponse{
				Status:       "SUCCESS",
				SessionToken: "mock session token",
				FactorResult: "Success",
			}

			j, _ := json.Marshal(reply)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(j)
			return
		}
		http.Error(w, "invalid mfa code", http.StatusUnauthorized)
		return
	}

	// push mfa
	reply := new(oktaAuthnResponse)
	if r.URL.Query().Get("success") != "" {
		reply.Status = "SUCCESS"
		reply.SessionToken = "mock session token"

		j, _ := json.Marshal(reply)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(j)
		return
	}

	reply.Status = "MFA_CHALLENGE"
	reply.FactorResult = "WAITING"
	reply.Links = map[string]interface{}{"next": map[string]string{"href": fmt.Sprintf("http://%s%s?success=1", r.Host, r.URL.Path)}}

	j, _ := json.Marshal(reply)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(j)
}
