package saml

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestNewBaseSamlClient(t *testing.T) {
	t.Run("bad url", func(t *testing.T) {
		_, err := NewSamlClient("not-a-url")
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("bad response", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("body"))
		}))
		defer s.Close()

		_, err := NewSamlClient(s.URL)
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("good", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<EntityDescriptor entityID="https://localhost:443/auth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://localhost:443/auth/SSOPOST/metaAlias/realm/saml-idp"/>
  </IDPSSODescriptor>
</EntityDescriptor>`)
		}))
		defer s.Close()

		c, err := NewSamlClient(s.URL)
		if err != nil {
			t.Error(err)
			return
		}
		c.SetCookieJar(new(cookiejar.Jar))

		if c.entityId != "https://localhost:443/auth" {
			t.Error("did not receive expected data in response")
		}
	})
}

func TestNewSamlClient(t *testing.T) {
	c := new(SamlClient)
	if c.Client() != c {
		t.Error("type mismatch")
	}
}

func TestBaseSamlClient_GatherCredentials(t *testing.T) {
	c := new(SamlClient)
	c.CredProvider = func(string, string) (s string, s2 string, e error) {
		return "user", "pass", nil
	}

	c.MfaTokenProvider = func() (s string, e error) {
		return "12345", nil
	}

	t.Run("simple", func(t *testing.T) {
		if err := c.GatherCredentials(); err != nil {
			t.Error(err)
			return
		}

		if c.Username != "user" || c.Password != "pass" || len(c.MfaToken) > 0 {
			t.Error("data mismatch")
		}
	})

	t.Run("mfa", func(t *testing.T) {
		c.MfaType = MfaTypeCode

		if err := c.GatherCredentials(); err != nil {
			t.Error(err)
			return
		}

		if c.Username != "user" || c.Password != "pass" || c.MfaToken != "12345" {
			t.Error("data mismatch")
		}
	})
}

func TestBaseSamlClient_SamlRequest(t *testing.T) {
	c := &SamlClient{
		httpClient: new(http.Client),
	}

	t.Run("empty body", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer s.Close()

		u, err := url.Parse(s.URL)
		if err != nil {
			t.Error(err)
			return
		}

		_, err = c.SamlRequest(u)
		if err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("malformed body", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("body"))
		}))
		defer s.Close()

		u, err := url.Parse(s.URL)
		if err != nil {
			t.Error(err)
			return
		}

		_, err = c.SamlRequest(u)
		if err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("good", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<html>
<head></head>
<body>
<form>
<input name="SAMLResponse">
your data here
</input>
</form>
</body>
</html>`))
		}))
		defer s.Close()

		u, err := url.Parse(s.URL)
		if err != nil {
			t.Error(err)
			return
		}

		_, err = c.SamlRequest(u)
		if err != nil {
			t.Error(err)
			return
		}
	})
}
