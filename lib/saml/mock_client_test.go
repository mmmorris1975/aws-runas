package saml

import (
	"testing"
)

func TestNewMockSamlClient(t *testing.T) {
	c, err := NewMockSamlClient("https://example.com/saml/auth")
	if err != nil {
		t.Error(err)
		return
	}

	if c.httpClient == nil {
		t.Error("bad HTTP client")
	}

	if c.CredProvider == nil || c.MfaTokenProvider == nil {
		t.Error("nil Cred or Mfa Provider")
	}
}

func TestMockSamlClient_Authenticate(t *testing.T) {
	c := &mockSamlClient{BaseAwsClient: new(BaseAwsClient)}

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
