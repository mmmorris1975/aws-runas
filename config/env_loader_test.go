package config

import (
	"os"
	"strconv"
	"testing"
	"time"
)

func TestEnvLoader_Config(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		c, err := DefaultEnvLoader.Config("")
		if err != nil {
			t.Error(err)
			return
		}

		if c == nil {
			t.Error("nil config")
			return
		}
	})
}

func TestEnvLoader_Config_ARN(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		_ = os.Setenv("JUMP_ROLE_ARN", "arn:aws:iam::0123456789:role/Admin")
		defer os.Unsetenv("JUMP_ROLE_ARN")

		c, err := DefaultEnvLoader.Config("")
		if err != nil {
			t.Error(err)
			return
		}

		a, err := c.JumpRoleARN()
		if err != nil {
			t.Error(err)
			return
		}

		if a.AccountID != "0123456789" {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("invalid", func(t *testing.T) {
		_ = os.Setenv("JUMP_ROLE_ARN", "aws:arn:iam::0123456789:role/Admin")
		defer os.Unsetenv("JUMP_ROLE_ARN")

		c, err := DefaultEnvLoader.Config("")
		if err != nil {
			t.Error(err)
			return
		}

		if _, err := c.JumpRoleARN(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("empty", func(t *testing.T) {
		_ = os.Setenv("JUMP_ROLE_ARN", "")
		defer os.Unsetenv("JUMP_ROLE_ARN")

		c, err := DefaultEnvLoader.Config("")
		if err != nil {
			t.Error(err)
			return
		}

		if _, err := c.JumpRoleARN(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestEnvLoader_Config_URL(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		_ = os.Setenv("SAML_AUTH_URL", "http://localhost/saml")
		defer os.Unsetenv("SAML_AUTH_URL")

		c, err := DefaultEnvLoader.Config("")
		if err != nil {
			t.Error(err)
			return
		}

		u, err := c.SamlURL()
		if err != nil {
			t.Error(err)
			return
		}

		if u == nil || u.Host != "localhost" {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("invalid", func(t *testing.T) {
		_ = os.Setenv("WEB_IDENTITY_AUTH_URL", "http://local|host/oauth2/auth")
		defer os.Unsetenv("WEB_IDENTITY_AUTH_URL")

		c, err := DefaultEnvLoader.Config("")
		if err != nil {
			t.Error(err)
			return
		}

		if _, err := c.WebIdentityURL(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("empty", func(t *testing.T) {
		_ = os.Setenv("WEB_IDENTITY_AUTH_URL", "")
		defer os.Unsetenv("WEB_IDENTITY_AUTH_URL")

		c, err := DefaultEnvLoader.Config("")
		if err != nil {
			t.Error(err)
			return
		}

		if _, err := c.WebIdentityURL(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestEnvLoader_Config_Duration(t *testing.T) {
	t.Run("good string duration", func(t *testing.T) {
		_ = os.Setenv("CREDENTIALS_DURATION", "12h")
		defer os.Unsetenv("CREDENTIALS_DURATION")

		c, err := DefaultEnvLoader.Config("")
		if err != nil {
			t.Error(err)
			return
		}

		if c.RoleCredentialDuration() != 12*time.Hour {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("good int duration", func(t *testing.T) {
		_ = os.Setenv("DURATION_SECONDS", "900")
		defer os.Unsetenv("DURATION_SECONDS")

		c, err := DefaultEnvLoader.Config("")
		if err != nil {
			t.Error(err)
			return
		}

		if c.RoleCredentialDuration() != 900*time.Second {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("good int raw", func(t *testing.T) {
		v := 3600 * 1000 * 1000 * 1000
		_ = os.Setenv("SESSION_TOKEN_DURATION", strconv.Itoa(v))
		defer os.Unsetenv("SESSION_TOKEN_DURATION")

		c, err := DefaultEnvLoader.Config("")
		if err != nil {
			t.Error(err)
			return
		}

		if c.SessionTokenDuration != 3600*time.Second {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("invalid string duration", func(t *testing.T) {
		_ = os.Setenv("SESSION_TOKEN_DURATION", "lasdfa")
		defer os.Unsetenv("SESSION_TOKEN_DURATION")

		if _, err := DefaultEnvLoader.Config(""); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("empty", func(t *testing.T) {
		_ = os.Setenv("CREDENTIALS_DURATION", "")
		defer os.Unsetenv("CREDENTIALS_DURATION")

		c, err := DefaultEnvLoader.Config("")
		if err != nil {
			t.Error(err)
			return
		}

		if c.RoleCredentialDuration() > 0 {
			t.Error("data mismatch")
		}
	})
}

func TestEnvLoader_Credentials(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		c, err := DefaultEnvLoader.Credentials("")
		if err != nil {
			t.Error(err)
			return
		}

		if len(c.SamlPassword) > 0 || len(c.WebIdentityPassword) > 0 {
			t.Error("found unexpected password data")
			return
		}
	})

	t.Run("all", func(t *testing.T) {
		_ = os.Setenv("SAML_PASSWORD", "mockSamlPassword")
		_ = os.Setenv("WEB_IDENTITY_PASSWORD", "mockWebIdPassword")
		defer func() {
			_ = os.Unsetenv("SAML_PASSWORD")
			_ = os.Unsetenv("WEB_IDENTITY_PASSWORD")
		}()

		c, err := DefaultEnvLoader.Credentials("")
		if err != nil {
			t.Error(err)
			return
		}

		if c.SamlPassword != "mockSamlPassword" || c.WebIdentityPassword != "mockWebIdPassword" {
			t.Error("data mismatch")
			return
		}
	})
}
