package saml

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewMockSamlClient(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "X-MockTest-Only,X-MockTest-NoAuth")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<EntityDescriptor entityID="https://localhost:443/auth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://%s/auth/saml"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, r.Host)
	}))
	defer s.Close()

	c, err := NewMockSamlClient(s.URL)
	if err != nil {
		t.Error(err)
		return
	}

	if c.ssoUrl.String() != s.URL+"/auth/saml" {
		t.Error("data mismatch")
	}
}

func TestMockSamlClient_Authenticate(t *testing.T) {
	c := &mockSamlClient{SamlClient: new(SamlClient)}

	t.Run("good", func(t *testing.T) {
		c.Username = "good"
		c.Password = "good"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})

	t.Run("bad", func(t *testing.T) {
		c.Username = "bad"
		c.Password = "bad"

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestMockSamlClient_AwsSaml(t *testing.T) {
	s, err := new(mockSamlClient).AwsSaml()
	if err != nil {
		t.Error(err)
		return
	}

	if s != "><" {
		t.Error("data mismatch")
	}
}

func TestMockSamlClient_GetIdentity(t *testing.T) {
	id, err := new(mockSamlClient).GetIdentity()
	if err != nil {
		t.Error(err)
		return
	}

	if id == nil || id.IdentityType != "user" || id.Username != "mock-user" {
		t.Error("data mismatch")
	}
}

func TestMockSamlClient_GetSessionDuration(t *testing.T) {
	d, err := new(mockSamlClient).GetSessionDuration()
	if err != nil {
		t.Error(err)
		return
	}

	if d != 12345 {
		t.Error("data mismatch")
	}
}

func TestMockSamlClient_Roles(t *testing.T) {
	r, err := new(mockSamlClient).Roles()
	if err != nil {
		t.Error(err)
		return
	}

	if len(r) > 0 {
		t.Error("data mismatch")
	}
}
