package saml

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestNewKeycloakSamlClient(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockKeycloakHandler))
	defer s.Close()

	t.Run("good", func(t *testing.T) {
		u := fmt.Sprintf("%s/auth/realms/master/protocol/saml/clients/aws", s.URL)

		c, err := NewKeycloakSamlClient(u)
		if err != nil {
			t.Error(err)
			return
		}

		if c.realm != "master" || c.clientId != "aws" {
			t.Error("data mismatch")
		}
	})

	t.Run("bad url", func(t *testing.T) {
		_, err := NewKeycloakSamlClient("not-a-url")
		if err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestKeycloakSamlClient_AwsSaml(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockKeycloakHandler))
	defer s.Close()

	c, err := newKeycloakClient(s)
	if err != nil {
		t.Error(err)
		return
	}

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
		k, err := newKeycloakClient(s)
		if err != nil {
			t.Error(err)
			return
		}
		k.rawSamlResponse = "abc123"

		if _, err := k.AwsSaml(); err != nil {
			t.Error(err)
			return
		}

		if k.rawSamlResponse != "abc123" || len(k.decodedSaml) > 0 {
			t.Error("data mismatch")
		}
	})
}

func TestKeycloakSamlClient_AuthenticateBasic(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockKeycloakHandler))
	defer s.Close()

	c, err := newKeycloakClient(s)
	if err != nil {
		t.Error(err)
		return
	}

	t.Run("good", func(t *testing.T) {
		c.Username = "gooduser"
		c.Password = "goodpassword"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})

	t.Run("bad", func(t *testing.T) {
		c.Username = "baduser"
		c.Password = "badpassword"

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected authentication failure")
		}
	})
}

func TestKeycloakSamlClient_AuthenticateMfa(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(mockKeycloakHandler))
	defer s.Close()

	c, err := newKeycloakClient(s)
	if err != nil {
		t.Error(err)
		return
	}

	c.Username = "mfauser"
	c.Password = "mfapassword"

	t.Run("good", func(t *testing.T) {
		c.MfaToken = "123456"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})

	t.Run("retry", func(t *testing.T) {
		c.MfaToken = "654321"
		c.MfaTokenProvider = func() (s string, e error) {
			return "123456", nil
		}

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})

	t.Run("no provider", func(t *testing.T) {
		c.MfaToken = ""
		c.MfaTokenProvider = nil

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive the expected error")
		}
	})
}

func newKeycloakClient(s *httptest.Server) (*keycloakSamlClient, error) {
	u, err := url.Parse(s.URL + "/auth/realms/master/protocol/saml/clients/aws")
	if err != nil {
		return nil, err
	}

	c := keycloakSamlClient{BaseAwsClient: new(BaseAwsClient)}
	c.authUrl = u
	c.httpClient = s.Client()
	c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	c.parseBaseUrl()
	c.parseRealm()
	c.parseClientId()

	return &c, nil
}

func mockKeycloakHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.URL.Path == "/auth/realms/master/protocol/saml/clients/aws" {
		body := `
<html>
<head></head>
<body>
  <form method="post" action="http://%s/auth/realms/master/login-actions/authenticate">
    <input type="hidden" name="SAMLResponse" value="PHNhbWw6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlU2Vzc2lvbk5hbWUiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+bXktc2FtbC11c2VyPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHBzOi8vYXdzLmFtYXpvbi5jb20vU0FNTC9BdHRyaWJ1dGVzL1Nlc3Npb25EdXJhdGlvbiI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj40MzIwMDwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJ1cm46b2lkOjEuMy42LjEuNC4xLjU5MjMuMS4xLjEuMTEiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+Mjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoxMjM0NTY3ODkwOnJvbGUvUG93ZXJVc2VyLGFybjphd3M6aWFtOjoxMjM0NTY3ODkwOnNhbWwtcHJvdmlkZXIvbXlTU088L3NhbWw6QXR0cmlidXRlVmFsdWU+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5hcm46YXdzOmlhbTo6MDk4NzY1NDMyMTpyb2xlL1Bvd2VyVXNlcixhcm46YXdzOmlhbTo6MDk4NzY1NDMyMTpzYW1sLXByb3ZpZGVyL215U1NPPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YXJuOmF3czppYW06OjExMTExMTExMTpyb2xlL0FkbWluLGFybjphd3M6aWFtOjoxMTExMTExMTE6c2FtbC1wcm92aWRlci9teVNTTzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoyMjIyMjIyMjI6cm9sZS9tYW5hZ2VkLXJvbGUvQWRtaW4sYXJuOmF3czppYW06OjIyMjIyMjIyMjpzYW1sLXByb3ZpZGVyL215U1NPPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YXJuOmF3czppYW06OjMzMzMzMzMzMzpyb2xlL0FkbWluLGFybjphd3M6aWFtOjozMzMzMzMzMzM6c2FtbC1wcm92aWRlci9teVNTTzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+Cg=="/>
  </form>
</body>
</html>
`
		fmt.Fprintf(w, body, r.Host)
	} else if r.URL.Path == "/auth/realms/master/login-actions/authenticate" {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if (r.PostForm.Get("username") == "gooduser" && r.PostForm.Get("password") == "goodpassword") || r.PostForm.Get("totp") == "123456" {
			body := `
<html>
<head></head>
<body>
  <form method="post" action="http://%s/auth/realms/master/login-actions/authenticate">
    <input type="hidden" name="SAMLResponse" value="PHNhbWw6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlU2Vzc2lvbk5hbWUiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+bXktc2FtbC11c2VyPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHBzOi8vYXdzLmFtYXpvbi5jb20vU0FNTC9BdHRyaWJ1dGVzL1Nlc3Npb25EdXJhdGlvbiI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj40MzIwMDwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJ1cm46b2lkOjEuMy42LjEuNC4xLjU5MjMuMS4xLjEuMTEiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+Mjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoxMjM0NTY3ODkwOnJvbGUvUG93ZXJVc2VyLGFybjphd3M6aWFtOjoxMjM0NTY3ODkwOnNhbWwtcHJvdmlkZXIvbXlTU088L3NhbWw6QXR0cmlidXRlVmFsdWU+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5hcm46YXdzOmlhbTo6MDk4NzY1NDMyMTpyb2xlL1Bvd2VyVXNlcixhcm46YXdzOmlhbTo6MDk4NzY1NDMyMTpzYW1sLXByb3ZpZGVyL215U1NPPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YXJuOmF3czppYW06OjExMTExMTExMTpyb2xlL0FkbWluLGFybjphd3M6aWFtOjoxMTExMTExMTE6c2FtbC1wcm92aWRlci9teVNTTzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoyMjIyMjIyMjI6cm9sZS9tYW5hZ2VkLXJvbGUvQWRtaW4sYXJuOmF3czppYW06OjIyMjIyMjIyMjpzYW1sLXByb3ZpZGVyL215U1NPPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YXJuOmF3czppYW06OjMzMzMzMzMzMzpyb2xlL0FkbWluLGFybjphd3M6aWFtOjozMzMzMzMzMzM6c2FtbC1wcm92aWRlci9teVNTTzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+Cg=="/>
  </form>
</body>
</html>
`
			fmt.Fprintf(w, body, r.Host)
		} else if r.PostForm.Get("username") == "mfauser" || len(r.PostForm.Get("totp")) > 0 {
			// return the MFA form
			body := `
<html>
<head></head>
<body>
  <form method="post" action="http://%s/auth/realms/master/login-actions/authenticate">
    <input id="totp" name="totp" type="text" />
  </form>
</body>
</html>
`
			fmt.Fprintf(w, body, r.Host)
			return
		} else {
			w.Write([]byte("whachutalkinbout"))
			return
		}
	} else {
		http.NotFound(w, r)
	}
}
