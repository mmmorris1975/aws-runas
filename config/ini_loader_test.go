package config

import (
	"io/ioutil"
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
		}
		t.Error("did not receive expected error")
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
		}
		t.Error("did not receive expected error")
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

func TestIniLoader_Profiles(t *testing.T) {
	p, err := DefaultIniLoader.Profiles(testConfig)
	if err != nil {
		t.Error(err)
		return
	}

	if len(p) != 9 {
		t.Error("did not receive expected number of profiles")
	}

	roles := make([]string, 0)
	for k, v := range p {
		if v {
			roles = append(roles, k)
		}
	}

	if len(roles) != 4 {
		t.Error("did not receive expected number of roles")
	}
}

func TestIniLoader_SaveProfile(t *testing.T) {
	// todo
	tf, err := ioutil.TempFile(t.TempDir(), t.Name())
	if err != nil {
		t.Error(err)
		return
	}

	os.Setenv("AWS_CONFIG_FILE", tf.Name())
	defer os.Unsetenv("AWS_CONFIG_FILE")

	t.Run("iam", func(t *testing.T) {
		cfg := &AwsConfig{
			ExternalId:  "testiam",
			RoleArn:     "testrole",
			SrcProfile:  "default",
			ProfileName: "iam",
		}

		if err := DefaultIniLoader.SaveProfile(cfg); err != nil {
			t.Error(err)
			return
		}

		f, err := loadFile(tf.Name())
		if err != nil {
			t.Error(err)
			return
		}

		if s := f.Section(cfg.ProfileName); s != nil {
			if s.HasKey("saml_auth_url") || s.HasKey("web_identity_auth_url") {
				t.Error("invalid profile returned")
			}

			cfg := new(AwsConfig)
			if err = s.MapTo(cfg); err != nil {
				t.Error(err)
				return
			}

			if cfg.ProfileName != "iam" || cfg.RoleArn != "testrole" || cfg.ExternalId != "testiam" {
				t.Error("data mismatch")
			}
		} else {
			t.Error("missing profile")
		}
	})

	t.Run("saml", func(t *testing.T) {
		cfg := &AwsConfig{
			SamlUrl:     "testsaml",
			RoleArn:     "testrole",
			ProfileName: "saml",
		}

		if err := DefaultIniLoader.SaveProfile(cfg); err != nil {
			t.Error(err)
			return
		}

		f, err := loadFile(tf.Name())
		if err != nil {
			t.Error(err)
			return
		}

		if s := f.Section(cfg.ProfileName); s != nil {
			if s.HasKey("external_id") || s.HasKey("web_identity_auth_url") {
				t.Error("invalid profile returned")
			}

			cfg := new(AwsConfig)
			if err = s.MapTo(cfg); err != nil {
				t.Error(err)
				return
			}

			if cfg.ProfileName != "saml" || cfg.RoleArn != "testrole" || cfg.SamlUrl != "testsaml" {
				t.Error("data mismatch")
			}
		} else {
			t.Error("missing profile")
		}
	})

	t.Run("oidc", func(t *testing.T) {
		cfg := &AwsConfig{
			WebIdentityUrl:         "testoidc",
			WebIdentityClientId:    "testclient",
			WebIdentityRedirectUri: "app:/callback",
			RoleArn:                "testrole",
			ProfileName:            "oidc",
		}

		if err := DefaultIniLoader.SaveProfile(cfg); err != nil {
			t.Error(err)
			return
		}

		f, err := loadFile(tf.Name())
		if err != nil {
			t.Error(err)
			return
		}

		if s := f.Section(cfg.ProfileName); s != nil {
			if s.HasKey("external_id") || s.HasKey("saml_auth_url") {
				t.Error("invalid profile returned")
			}

			cfg := new(AwsConfig)
			if err = s.MapTo(cfg); err != nil {
				t.Error(err)
				return
			}

			if cfg.ProfileName != "oidc" || cfg.RoleArn != "testrole" || cfg.WebIdentityUrl != "testoidc" ||
				cfg.WebIdentityClientId != "testclient" || cfg.WebIdentityRedirectUri != "app:/callback" {
				t.Error("data mismatch")
			}
		} else {
			t.Error("missing profile")
		}
	})

	t.Run("nil config", func(t *testing.T) {
		if err := DefaultIniLoader.SaveProfile(nil); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("missing profile name", func(t *testing.T) {
		if err := DefaultIniLoader.SaveProfile(&AwsConfig{RoleArn: "test"}); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("missing role arn", func(t *testing.T) {
		if err := DefaultIniLoader.SaveProfile(&AwsConfig{ProfileName: "test"}); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestIniLoader_SaveCredentials(t *testing.T) {
	tf, err := ioutil.TempFile(t.TempDir(), t.Name())
	if err != nil {
		t.Error(err)
		return
	}

	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", tf.Name())
	defer os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")

	t.Run("saml", func(t *testing.T) {
		if err := DefaultIniLoader.SaveCredentials("saml", &AwsCredentials{SamlPassword: "testsaml"}); err != nil {
			t.Error(err)
			return
		}

		f, err := loadFile(tf.Name())
		if err != nil {
			t.Error(err)
			return
		}

		if s := f.Section("saml"); s != nil {
			c := new(AwsCredentials)
			if err = s.MapTo(c); err != nil {
				t.Error(err)
				return
			}

			if c.SamlPassword != "testsaml" {
				t.Error("data mismatch")
			}
		} else {
			t.Error("missing profile")
		}
	})

	t.Run("oidc", func(t *testing.T) {
		if err := DefaultIniLoader.SaveCredentials("oidc", &AwsCredentials{WebIdentityPassword: "testweb"}); err != nil {
			t.Error(err)
			return
		}

		f, err := loadFile(tf.Name())
		if err != nil {
			t.Error(err)
			return
		}

		if s := f.Section("oidc"); s != nil {
			c := new(AwsCredentials)
			if err = s.MapTo(c); err != nil {
				t.Error(err)
				return
			}

			if c.WebIdentityPassword != "testweb" {
				t.Error("data mismatch")
			}
		} else {
			t.Error("missing profile")
		}
	})

	t.Run("both", func(t *testing.T) {
		// there could be some case (very unlikely) where the SAML and OIDC endpoint are the same, using the same password,
		// so it would be more efficient if you store the credentials in a single place.  If there's one thing you should
		// be, you should be efficient.
		c := &AwsCredentials{
			SamlPassword:        "testboth",
			WebIdentityPassword: "testboth",
		}

		if err := DefaultIniLoader.SaveCredentials("both", c); err != nil {
			t.Error(err)
			return
		}

		f, err := loadFile(tf.Name())
		if err != nil {
			t.Error(err)
			return
		}

		if s := f.Section("both"); s != nil {
			c = new(AwsCredentials)
			if err = s.MapTo(c); err != nil {
				t.Error(err)
				return
			}

			if c.SamlPassword != "testboth" || c.WebIdentityPassword != "testboth" {
				t.Error("data mismatch")
			}
		} else {
			t.Error("missing profile")
		}
	})

	t.Run("empty creds", func(t *testing.T) {
		if err := DefaultIniLoader.SaveCredentials("test", new(AwsCredentials)); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("nil creds", func(t *testing.T) {
		if err := DefaultIniLoader.SaveCredentials("test", nil); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("empty profile", func(t *testing.T) {
		if err := DefaultIniLoader.SaveCredentials("", &AwsCredentials{SamlPassword: "test"}); err == nil {
			t.Error("did not receive expected error")
		}
	})
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
