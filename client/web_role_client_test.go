package client

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/mmmorris1975/aws-runas/client/external"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
	"github.com/mmmorris1975/aws-runas/shared"
	"net/http"
	"testing"
)

func TestNewWebRoleClient(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		// must set IdentityProviderName to avoid client auto-detection
		cfg := new(WebRoleClientConfig)
		cfg.OidcClientConfig = external.OidcClientConfig{
			AuthenticationClientConfig: external.AuthenticationClientConfig{
				IdentityProviderName: "okta",
				Username:             "mockUser",
			},
		}

		c := NewWebRoleClient(aws.Config{}, "http://oidc.mock.local/auth", cfg)
		if c == nil {
			t.Error("nil client returned")
			return
		}
	})

	t.Run("nil client config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewWebRoleClient with nil client config")
			}
		}()
		NewWebRoleClient(aws.Config{}, "", nil)
	})
}

func TestWebRoleClient_Identity(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := &webRoleClient{webClient: &mockWebClient{false}}
		id, err := c.Identity()
		if err != nil {
			t.Error(err)
			return
		}

		if id == nil || id.Username != "web_user" || id.IdentityType != "user" || id.Provider != "mockWebClient" {
			t.Error("data mismatch")
		}
	})

	t.Run("error", func(t *testing.T) {
		c := &webRoleClient{webClient: &mockWebClient{true}}
		if _, err := c.Identity(); err == nil {
			t.Error("did not eceive expected error")
			return
		}
	})
}

func TestWebRoleClient_Roles(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := &webRoleClient{webClient: &mockWebClient{false}}
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
		c := &webRoleClient{webClient: &mockWebClient{true}}
		if _, err := c.Roles(); err == nil {
			t.Error("did not eceive expected error")
			return
		}
	})
}

func TestWebRoleClient_Credentials(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := &webRoleClient{
			webClient:    new(mockWebClient),
			roleProvider: new(mockWebRoleProvider),
			logger:       new(shared.DefaultLogger),
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

	t.Run("bad fetch", func(t *testing.T) {
		var p mockWebRoleProvider = true
		c := &webRoleClient{
			webClient:    new(mockWebClient),
			roleProvider: &p,
			tokenFile:    "i am not a real file",
		}
		c.awsCredCache = aws.NewCredentialsCache(c.roleProvider)

		if _, err := c.Credentials(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestWebRoleClient_ConfigProvider(t *testing.T) {
	c := &webRoleClient{session: aws.Config{}}
	if cp := c.ConfigProvider(); cp.Credentials != c.session.Credentials {
		t.Error("invalid config provider")
	}
}

func TestWebRoleClient_ClearCache(t *testing.T) {
	c := &webRoleClient{roleProvider: credentials.NewWebRoleProvider(aws.Config{}, "mock_role")}
	c.logger = new(shared.DefaultLogger)

	if err := c.ClearCache(); err != nil {
		t.Error(err)
	}
}

type mockWebClient struct {
	sendError bool
}

func (c *mockWebClient) Identity() (*identity.Identity, error) {
	if c.sendError {
		return nil, errors.New("error: Identity()")
	}

	return &identity.Identity{
		IdentityType: "user",
		Provider:     "mockWebClient",
		Username:     "web_user",
	}, nil
}

func (c *mockWebClient) Roles(...string) (*identity.Roles, error) {
	if c.sendError {
		return nil, errors.New("error: Roles()")
	}

	r := identity.Roles([]string{"role1", "role2"})
	return &r, nil
}

func (c *mockWebClient) Authenticate() error {
	return c.AuthenticateWithContext(context.Background())
}

func (c *mockWebClient) AuthenticateWithContext(context.Context) error {
	if c.sendError {
		return errors.New("error: Authenticate()")
	}
	return nil
}

func (c *mockWebClient) SetCookieJar(http.CookieJar) {
	// return
}

func (c *mockWebClient) IdentityToken() (*credentials.OidcIdentityToken, error) {
	return c.IdentityTokenWithContext(context.Background())
}

func (c *mockWebClient) IdentityTokenWithContext(context.Context) (*credentials.OidcIdentityToken, error) {
	if c.sendError {
		return nil, errors.New("error: IdentityToken()")
	}
	t := credentials.OidcIdentityToken("mockWebIdentityToken")
	return &t, nil
}
