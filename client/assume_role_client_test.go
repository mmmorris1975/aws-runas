package client

import (
	awscreds "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/awstesting/mock"
	"github.com/mmmorris1975/aws-runas/credentials"
	"os"
	"testing"
)

func TestNewAssumeRoleClient(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := NewAssumeRoleClient(mock.Session, &AssumeRoleClientConfig{RoleSessionName: "mockSessionName"})
		if c == nil || c.creds == nil || c.ident == nil {
			t.Error("invalid client")
			return
		}
	})

	t.Run("nil config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewAssumeRoleProvider with nil config")
			}
		}()
		NewAssumeRoleClient(nil, new(AssumeRoleClientConfig))
	})

	t.Run("nil client config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewAssumeRoleProvider with nil config")
			}
		}()
		NewAssumeRoleClient(mock.Session, nil)
	})

	t.Run("empty client config", func(t *testing.T) {
		// avoid reaching out to aws for identity with unset RoleSessionName
		_ = os.Setenv("AWS_SHARED_CREDENTIALS_FILE", os.DevNull)
		for _, e := range []string{"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY"} {
			os.Unsetenv(e)
		}

		c := NewAssumeRoleClient(mock.Session, new(AssumeRoleClientConfig))
		if c == nil {
			t.Error("nil client")
			return
		}
	})
}

func TestAssumeRoleClient_Identity(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		id, err := newAssumeRoleClient().Identity()
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
		c := newAssumeRoleClient()
		c.ident = &mockIdent{true}

		if _, err := c.Identity(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestAssumeRoleClient_Roles(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		roles, err := newAssumeRoleClient().Roles()
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
		c := newAssumeRoleClient()
		c.ident = &mockIdent{true}

		if _, err := c.Roles(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestAssumeRoleClient_Credentials(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		creds, err := newAssumeRoleClient().Credentials()
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
		c := newAssumeRoleClient()
		c.creds = awscreds.NewCredentials(&mockCredProvider{sendError: true})

		if _, err := c.Credentials(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestAssumeRoleClient_ConfigProvider(t *testing.T) {
	c := newAssumeRoleClient()
	c.session = mock.Session
	if cp := c.ConfigProvider(); cp == nil {
		t.Error("invalid config provider")
	}
}

func TestAssumeRoleClient_ClearCache(t *testing.T) {
	c := newAssumeRoleClient()
	c.provider = credentials.NewAssumeRoleProvider(mock.Session, "mockRole")

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

func newAssumeRoleClient() *assumeRoleClient {
	c := &assumeRoleClient{baseIamClient: new(baseIamClient)}
	c.creds = awscreds.NewCredentials(new(mockCredProvider))
	c.ident = new(mockIdent)
	return c
}
