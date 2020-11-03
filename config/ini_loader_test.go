package config

import (
	"os"
	"testing"
	"time"
)

func TestIniLoader_Config(t *testing.T) {
	t.Run("bad file", func(t *testing.T) {
		_ = os.Setenv("AWS_CONFIG_FILE", "this_is_not_A_file")
		defer os.Unsetenv("AWS_CONFIG_FILE")

		if _, err := DefaultIniLoader.Config("default"); err != nil {
			if _, ok := err.(*os.PathError); !ok {
				t.Error("unexpected error type received (was not *os.PathError)")
			}
			return
		} else {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("bad profile", func(t *testing.T) {
		if _, err := DefaultIniLoader.Config("non-existent", testConfig); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("empty data", func(t *testing.T) {
		if _, err := DefaultIniLoader.Config("", testConfig); err != nil {
			t.Error(err)
			return
		}
	})
}

func TestIniLoader_Config_ARN(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c, err := DefaultIniLoader.Config("valid", testConfig)
		if err != nil {
			t.Error(err)
			return
		}

		a, err := c.RoleARN()
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
		c, err := DefaultIniLoader.Config("invalid_arn", testConfig)
		if err != nil {
			t.Error(err)
			return
		}

		if _, err := c.RoleARN(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("empty", func(t *testing.T) {
		c, err := DefaultIniLoader.Config("invalid_arn", testConfig)
		if err != nil {
			t.Error(err)
			return
		}

		if _, err := c.RoleARN(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestIniLoader_Config_Duration(t *testing.T) {
	t.Run("good string duration", func(t *testing.T) {
		c, err := DefaultIniLoader.Config("valid", testConfig)
		if err != nil {
			t.Error(err)
			return
		}

		if c.RoleCredentialDuration() != 12*time.Hour {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("good int", func(t *testing.T) {
		c, err := DefaultIniLoader.Config("int_duration", testConfig)
		if err != nil {
			t.Error(err)
			return
		}

		if c.RoleCredentialDuration() != 900*time.Second {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("invalid string duration", func(t *testing.T) {
		c, err := DefaultIniLoader.Config("invalid_duration", testConfig)
		if err != nil {
			t.Error(err)
			return
		}

		// reports as zero value
		if c.RoleCredentialDuration() != 0 {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("empty", func(t *testing.T) {
		c, err := DefaultIniLoader.Config("empty_duration", testConfig)
		if err != nil {
			t.Error(err)
			return
		}

		// reports as zero value
		if c.RoleCredentialDuration() != 0 {
			t.Error("data mismatch")
			return
		}
	})
}

func TestIniLoader_Config_SourceProfile(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c, err := DefaultIniLoader.Config("src", testConfig)
		if err != nil {
			t.Error(err)
			return
		}

		if c.SourceProfile() == nil || len(c.SourceProfile().RoleArn) < 1 {
			t.Error("did not set source profile")
		}

		if c.MfaSerial != "mockMfa" {
			t.Error("did not set local profile config")
		}
	})

	t.Run("invalid source profile", func(t *testing.T) {
		if _, err := DefaultIniLoader.Config("invalid_src", testConfig); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestIniLoader_Credentials(t *testing.T) {
	t.Run("bad file", func(t *testing.T) {
		_ = os.Setenv("AWS_SHARED_CREDENTIALS_FILE", "this_is_not_A_file")
		defer os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")

		if _, err := DefaultIniLoader.Credentials("default"); err != nil {
			if _, ok := err.(*os.PathError); !ok {
				t.Error("unexpected error type received (was not *os.PathError)")
			}
			return
		} else {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("bad profile", func(t *testing.T) {
		if _, err := DefaultIniLoader.Credentials("non-existent", testCredentials); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("profile no data", func(t *testing.T) {
		c, err := DefaultIniLoader.Credentials("default", testCredentials)
		if err != nil {
			t.Error(err)
			return
		}

		if len(c.SamlPassword) > 0 || len(c.WebIdentityPassword) > 0 {
			t.Error("data mismatch")
		}
	})

	t.Run("empty profile", func(t *testing.T) {
		if _, err := DefaultIniLoader.Credentials("", testCredentials); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("saml", func(t *testing.T) {
		c, err := DefaultIniLoader.Credentials("saml", testCredentials)
		if err != nil {
			t.Error(err)
			return
		}

		if c.SamlPassword != "mockSaml" {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("web", func(t *testing.T) {
		c, err := DefaultIniLoader.Credentials("web", testCredentials)
		if err != nil {
			t.Error(err)
			return
		}

		if c.WebIdentityPassword != "mockWeb" {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("both", func(t *testing.T) {
		c, err := DefaultIniLoader.Credentials("both", testCredentials)
		if err != nil {
			t.Error(err)
			return
		}

		if c.SamlPassword != "mockSaml" || c.WebIdentityPassword != "mockWeb" {
			t.Error("data mismatch")
			return
		}
	})
}

func TestIniLoader_Roles(t *testing.T) {
	roles, err := DefaultIniLoader.Roles(testConfig)
	if err != nil {
		t.Error(err)
		return
	}

	if len(roles) < 4 {
		t.Error("did not receive expected number of roles")
	}
}

var testCredentials = []byte(`
[default]
aws_access_key_id = mockAk
aws_secret_access_key = mockSk

[saml]
saml_password = mockSaml

[web]
web_identity_password = mockWeb

[both]
saml_password = mockSaml
web_identity_password = mockWeb
`)

var testConfig = []byte(`
[default]

[profile valid]
credentials_duration = 12h
role_arn = arn:aws:iam::0123456789:role/Admin

[invalid_arn]
role_arn = aws:arn:iam::0123456789:role/Admin

[profile empty_arn]
role_arn =

[profile int_duration]
duration_seconds = 900

[invalid_duration]
credentials_duration = alsga

[profile empty_duration]
credentials_duration =

[profile src]
source_profile = valid
mfa_serial = mockMfa

[profile invalid_src]
source_profile = error_404
role_arn = arn:aws:iam::0123456789:role/Admin
`)
