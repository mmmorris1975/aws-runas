package client

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/mmmorris1975/aws-runas/client/external"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
	"net/http"
	"testing"
)

func TestNewSamlRoleClient(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		// must set IdentityProviderName to avoid client auto-detection
		cfg := &SamlRoleClientConfig{
			AuthenticationClientConfig: external.AuthenticationClientConfig{IdentityProviderName: "okta"},
		}
		c := NewSamlRoleClient(aws.Config{}, "http://saml.mock.local/saml", cfg)
		if c == nil {
			t.Error("nil client returned")
			return
		}
	})

	t.Run("nil client config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewSamlRoleClient with nil client config")
			}
		}()
		NewSamlRoleClient(aws.Config{}, "", nil)
	})
}

func TestSamlRoleClient_Identity(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := &samlRoleClient{samlClient: &mockSamlClient{false}}
		id, err := c.Identity()
		if err != nil {
			t.Error(err)
			return
		}

		if id == nil || id.Username != "saml_user" || id.IdentityType != "user" || id.Provider != "mockSamlProvider" {
			t.Error("data mismatch")
		}
	})

	t.Run("error", func(t *testing.T) {
		c := &samlRoleClient{samlClient: &mockSamlClient{true}}
		if _, err := c.Identity(); err == nil {
			t.Error("did not eceive expected error")
			return
		}
	})
}

func TestSamlRoleClient_Roles(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := &samlRoleClient{samlClient: &mockSamlClient{false}}
		roles, err := c.Roles()
		if err != nil {
			t.Error(err)
			return
		}

		if roles == nil || len(*roles) < 2 {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("error", func(t *testing.T) {
		c := &samlRoleClient{samlClient: &mockSamlClient{true}}
		if _, err := c.Roles(); err == nil {
			t.Error("did not eceive expected error")
			return
		}
	})
}

func TestSamlRoleClient_Credentials(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := &samlRoleClient{
			samlClient:   new(mockSamlClient),
			roleProvider: new(mockSamlRoleProvider),
		}
		c.awsCredCache = aws.NewCredentialsCache(c.roleProvider)

		creds, err := c.Credentials()
		if err != nil {
			t.Error(err)
			return
		}

		if !creds.Value().HasKeys() {
			t.Error("invalid credentials")
		}
	})

	t.Run("bad saml fetch", func(t *testing.T) {
		var p mockSamlRoleProvider = true
		c := &samlRoleClient{
			samlClient:   &mockSamlClient{sendError: true},
			roleProvider: &p,
		}
		c.awsCredCache = aws.NewCredentialsCache(c.roleProvider)

		if _, err := c.Credentials(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestSamlRoleClient_ConfigProvider(t *testing.T) {
	c := &samlRoleClient{session: aws.Config{}}
	if cp := c.ConfigProvider(); cp.Credentials != c.session.Credentials {
		t.Error("invalid config provider")
	}
}

func TestSamlRoleClient_ClearCache(t *testing.T) {
	saml := credentials.SamlAssertion("bogus")
	c := &samlRoleClient{roleProvider: credentials.NewSamlRoleProvider(aws.Config{}, "mock_role", &saml)}
	if err := c.ClearCache(); err != nil {
		t.Error(err)
	}
}

type mockSamlClient struct {
	sendError bool
}

func (c *mockSamlClient) Identity() (*identity.Identity, error) {
	if c.sendError {
		return nil, errors.New("error: Identity()")
	}

	return &identity.Identity{
		IdentityType: "user",
		Provider:     "mockSamlProvider",
		Username:     "saml_user",
	}, nil
}

func (c *mockSamlClient) Roles(...string) (*identity.Roles, error) {
	if c.sendError {
		return nil, errors.New("error: Roles()")
	}

	r := identity.Roles([]string{"role1", "role2"})
	return &r, nil
}

// func (c *mockSamlClient) RoleDetails() (*external.RoleDetails, error) {
//	panic("implement me")
// }

func (c *mockSamlClient) Authenticate() error {
	return c.AuthenticateWithContext(context.Background())
}

func (c *mockSamlClient) AuthenticateWithContext(context.Context) error {
	if c.sendError {
		return errors.New("error: Authenticate()")
	}
	return nil
}

func (c *mockSamlClient) SetCookieJar(http.CookieJar) {
	// return
}

func (c *mockSamlClient) SamlAssertion() (*credentials.SamlAssertion, error) {
	return c.SamlAssertionWithContext(context.Background())
}

func (c *mockSamlClient) SamlAssertionWithContext(context.Context) (*credentials.SamlAssertion, error) {
	if c.sendError {
		return new(credentials.SamlAssertion), errors.New("error: AwsSaml()")
	}
	saml := credentials.SamlAssertion("mockSamlAssertion")
	return &saml, nil
}
