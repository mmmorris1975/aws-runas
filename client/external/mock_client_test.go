package external

import "testing"

func TestNewMockClient(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c, err := NewMockClient("http://localhost")
		if err != nil {
			t.Fatal("err")
		}

		if c == nil {
			t.Fatal("nil client")
		}
	})

	t.Run("bad url", func(t *testing.T) {
		if _, err := NewMockClient("ftp://example.org"); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestMockClient_Authenticate(t *testing.T) {
	if err := new(mockClient).Authenticate(); err != nil {
		t.Error(err)
	}
}

func TestMockClient_Identity(t *testing.T) {
	if _, err := new(mockClient).Identity(); err != nil {
		t.Error(err)
	}
}

func TestMockClient_IdentityToken(t *testing.T) {
	if _, err := new(mockClient).IdentityToken(); err != nil {
		t.Error(err)
	}
}

func TestMockClient_SamlAssertion(t *testing.T) {
	if _, err := new(mockClient).SamlAssertion(); err != nil {
		t.Error(err)
	}
}
