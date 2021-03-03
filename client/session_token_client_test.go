package client

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/mmmorris1975/aws-runas/credentials"
	"testing"
)

func TestNewSessionTokenClient(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := NewSessionTokenClient(aws.Config{}, new(SessionTokenClientConfig))
		if c == nil || c.creds == nil || c.ident == nil {
			t.Error("invalid client")
			return
		}
	})

	t.Run("nil client config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewAssumeRoleProvider with nil config")
			}
		}()
		NewSessionTokenClient(aws.Config{}, nil)
	})
}

func TestSessionTokenClient_Identity(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		id, err := newSessionTokenClient().Identity()
		if err != nil {
			t.Error(err)
			return
		}

		if id.Username != "mockUser" || id.IdentityType != "user" || id.Provider != "MockIdentityProvider" {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("error", func(t *testing.T) {
		c := newSessionTokenClient()
		c.ident = &mockIdent{true}

		if _, err := c.Identity(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestSessionTokenClient_Roles(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		roles, err := newSessionTokenClient().Roles()
		if err != nil {
			t.Error(err)
			return
		}

		if len(*roles) < 2 {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("error", func(t *testing.T) {
		c := newSessionTokenClient()
		c.ident = &mockIdent{true}

		if _, err := c.Roles(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestSessionTokenClient_Credentials(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		creds, err := newSessionTokenClient().Credentials()
		if err != nil {
			t.Error(err)
			return
		}

		if creds.AccessKeyId != "mockAK" || creds.SecretAccessKey != "mockSK" || creds.Token != "mockST" {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("error", func(t *testing.T) {
		c := newSessionTokenClient()
		c.creds = aws.NewCredentialsCache(&mockCredProvider{sendError: true})

		if _, err := c.Credentials(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("nil creds client", func(t *testing.T) {
		c := newSessionTokenClient()
		c.creds = nil

		if _, err := c.Credentials(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestSessionTokenClient_ConfigProvider(t *testing.T) {
	c := newSessionTokenClient()
	c.session = aws.Config{}
	if cp := c.ConfigProvider(); cp.Region != c.session.Region {
		t.Error("invalid config provider")
	}
}

func TestSessionTokenClient_ClearCache(t *testing.T) {
	c := newSessionTokenClient()
	c.provider = credentials.NewSessionTokenProvider(aws.Config{})

	t.Run("no cache", func(t *testing.T) {
		c.provider.Cache = nil
		if err := c.ClearCache(); err != nil {
			t.Error(err)
		}
	})

	t.Run("with cache", func(t *testing.T) {
		c.provider.Cache = &memCredCache{
			creds: &credentials.Credentials{
				AccessKeyId:     "mockAk",
				SecretAccessKey: "mockSk",
				Token:           "mockToken",
			},
		}

		if err := c.ClearCache(); err != nil {
			t.Error(err)
			return
		}

		if !c.provider.Cache.Load().Expiration.IsZero() {
			t.Error("invalid cache state")
		}
	})
}

func newSessionTokenClient() *sessionTokenClient {
	c := &sessionTokenClient{baseIamClient: new(baseIamClient)}
	c.creds = aws.NewCredentialsCache(new(mockCredProvider))
	c.ident = new(mockIdent)
	return c
}
