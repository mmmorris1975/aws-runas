package saml

import (
	"net/http/cookiejar"
	"testing"
)

func TestBaseAwsClient_Client(t *testing.T) {
	c := new(BaseAwsClient)
	if c != c.Client() {
		t.Error("data mismatch")
	}
}

func TestBaseAwsClient_GetIdentity(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := goodClient()
		id, err := c.GetIdentity()
		if err != nil {
			t.Error(err)
			return
		}

		if id == nil || id.Provider != IdentityProviderSaml || id.IdentityType != "user" || id.Username != "my-saml-user" {
			t.Error("data mismatch")
		}
	})

	t.Run("bad", func(t *testing.T) {
		c := badClient()
		if _, err := c.GetIdentity(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestBaseAwsClient_GetSessionDuration(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := goodClient()
		d, err := c.GetSessionDuration()
		if err != nil {
			t.Error(err)
			return
		}

		if d != 43200 {
			t.Error("data mismatch")
		}
	})

	t.Run("bad", func(t *testing.T) {
		c := badClient()
		if _, err := c.GetSessionDuration(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestBaseAwsClient_Roles(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := goodClient()
		r, err := c.Roles()
		if err != nil {
			t.Error(err)
			return
		}

		if r == nil || len(r) < 3 {
			t.Error("data mismatch")
		}
	})

	t.Run("bad", func(t *testing.T) {
		c := badClient()
		r, err := c.Roles()
		if err != nil {
			t.Error(err)
			return
		}

		if len(r) > 0 {
			t.Error("received a valid role list")
		}
	})
}

func TestBaseAwsClient_SetCookieJar(t *testing.T) {
	j, err := cookiejar.New(nil)
	if err != nil {
		t.Error(err)
		return
	}

	c := new(BaseAwsClient)
	c.SetCookieJar(j)
	if c.httpClient == nil || c.httpClient.Jar == nil {
		t.Error("nil http client data")
	}
}

func goodClient() *BaseAwsClient {
	c, _ := newBaseAwsClient("http://example.com/auth/saml")
	c.rawSamlResponse = "PHNhbWw6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlU2Vzc2lvbk5hbWUiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+bXktc2FtbC11c2VyPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHBzOi8vYXdzLmFtYXpvbi5jb20vU0FNTC9BdHRyaWJ1dGVzL1Nlc3Npb25EdXJhdGlvbiI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj40MzIwMDwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJ1cm46b2lkOjEuMy42LjEuNC4xLjU5MjMuMS4xLjEuMTEiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+Mjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoxMjM0NTY3ODkwOnJvbGUvUG93ZXJVc2VyLGFybjphd3M6aWFtOjoxMjM0NTY3ODkwOnNhbWwtcHJvdmlkZXIvbXlTU088L3NhbWw6QXR0cmlidXRlVmFsdWU+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5hcm46YXdzOmlhbTo6MDk4NzY1NDMyMTpyb2xlL1Bvd2VyVXNlcixhcm46YXdzOmlhbTo6MDk4NzY1NDMyMTpzYW1sLXByb3ZpZGVyL215U1NPPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YXJuOmF3czppYW06OjExMTExMTExMTpyb2xlL0FkbWluLGFybjphd3M6aWFtOjoxMTExMTExMTE6c2FtbC1wcm92aWRlci9teVNTTzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoyMjIyMjIyMjI6cm9sZS9tYW5hZ2VkLXJvbGUvQWRtaW4sYXJuOmF3czppYW06OjIyMjIyMjIyMjpzYW1sLXByb3ZpZGVyL215U1NPPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YXJuOmF3czppYW06OjMzMzMzMzMzMzpyb2xlL0FkbWluLGFybjphd3M6aWFtOjozMzMzMzMzMzM6c2FtbC1wcm92aWRlci9teVNTTzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+Cg=="
	return c
}

func badClient() *BaseAwsClient {
	c, _ := newBaseAwsClient("http://example.com/auth/saml")
	c.rawSamlResponse = ""
	return c
}
