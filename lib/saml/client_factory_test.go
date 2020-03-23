package saml

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetClientMock(t *testing.T) {
	// test explicit provider setting
	c, err := GetClient("mock", "https://my-mock-saml.local")
	if err != nil {
		t.Error(err)
		return
	}

	if _, ok := c.(*mockSamlClient); !ok {
		t.Error("did not get correct client type")
	}
}

func TestGetClientUnknown(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("body"))
	}))
	defer s.Close()

	_, err := GetClient("", s.URL)
	if err == nil {
		t.Error("did not get expected error")
	}
}

func TestGetClientForgerock(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "X-OpenAM-Username,X-OpenAM-Password")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<EntityDescriptor entityID="https://localhost:443/auth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://%s/auth/SSOPOST/metaAlias/realm/saml-idp"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, r.Host)
	}))
	defer s.Close()

	c, err := GetClient("", fmt.Sprintf(`%s/auth/json/realms/mock-test/authenticate`, s.URL))
	if err != nil {
		t.Error(err)
		return
	}

	if _, ok := c.(*forgerockSamlClient); !ok {
		t.Error("did not get correct client type")
	}
}

func TestGetClientKeycloak(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "AUTH_SESSION_ID",
			Value: "xxxxxx",
		})

		http.SetCookie(w, &http.Cookie{
			Name:  "KC_RESTART",
			Value: "yyyyyy",
		})

		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<EntitiesDescriptor Name="urn:keycloak" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <EntityDescriptor entityID="http://%s/auth/realms/master">
    <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://%s/auth/realms/master/protocol/saml"/>
    </IDPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>`, r.Host, r.Host)
	}))
	defer s.Close()

	c, err := GetClient("", fmt.Sprintf("%s/auth/realms/master/protocol/saml/clients/aws", s.URL))
	if err != nil {
		t.Error(err)
		return
	}

	if _, ok := c.(*keycloakSamlClient); !ok {
		t.Error("did not get correct client type")
	}
}
