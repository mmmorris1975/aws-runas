package config

import (
	"github.com/aws/aws-sdk-go/aws/defaults"
	"os"
	"testing"
)

func TestNewSharedCfgConfigHandlerNilOpts(t *testing.T) {
	defer func() {
		if x := recover(); x != nil {
			t.Errorf("Unexpected panic from NewSharedCfgConfigHandler() with nil options")
		}
	}()
	NewSharedCfgConfigHandler(nil)
}

func TestNewSharedCfgConfigHandlerAllEnvVars(t *testing.T) {
	os.Setenv("AWS_DEFAULT_PROFILE", "alt_default")
	defer os.Unsetenv("AWS_DEFAULT_PROFILE")
	os.Setenv("AWS_CONFIG_FILE", "test/aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")
	os.Setenv("AWS_PROFILE", "basic")
	defer os.Unsetenv("AWS_PROFILE")
	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", defaults.SharedCredentialsFilename())
	defer os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")

	c := new(AwsConfig)
	h := NewSharedCfgConfigHandler(nil)

	if err := h.Config(c); err != nil {
		t.Errorf("Error getting config: %v", err)
	}

	if c.GetRegion() != "us-west-2" || c.GetMfaSerial() != "12345678" {
		t.Errorf("Unexpected result in Config object: %+v", c)
	}
}

func TestNewSharedCfgConfigHandlerBadFileVars(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", "config")
	defer os.Unsetenv("AWS_CONFIG_FILE")
	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", "credentials")
	defer os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")

	h := NewSharedCfgConfigHandler(nil)
	if err := h.Config(new(AwsConfig)); err == nil {
		t.Errorf("Unexpected success when calling Config with bad config file env vars")
	}
}

func TestNewSharedCfgConfigHandlerCustomDefaultProfile(t *testing.T) {
	os.Unsetenv("AWS_REGION")
	os.Unsetenv("AWS_PROFILE")
	os.Setenv("AWS_DEFAULT_PROFILE", "alt_default")
	defer os.Unsetenv("AWS_DEFAULT_PROFILE")
	os.Setenv("AWS_CONFIG_FILE", "test/aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")

	c := new(AwsConfig)
	h := NewSharedCfgConfigHandler(new(ConfigHandlerOpts))

	if err := h.Config(c); err != nil {
		t.Errorf("Error getting config: %v", err)
	}
	t.Logf("DP: %+v", c.defaultProfile)
	if c.GetRegion() != "us-west-1" || c.GetMfaSerial() != "12345678" {
		t.Errorf("Unexpected result in Config object: %+v", c)
	}
}

func TestSharedCfgConfigHandler(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", "test/aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")

	t.Run("ProfileEnv", func(t *testing.T) {
		os.Setenv("AWS_PROFILE", "has_role_inherit_mfa")
		defer os.Unsetenv("AWS_PROFILE")

		c := new(AwsConfig)
		h := NewSharedCfgConfigHandler(nil)
		if err := h.Config(c); err != nil {
			t.Errorf("Error getting config: %v", err)
		}

		if c.GetRegion() != "us-west-1" || c.GetMfaSerial() != "12345678" {
			t.Errorf("Unexpected result in Config object: %+v", c)
		}
	})

	t.Run("ProfileMeth", func(t *testing.T) {
		c := new(AwsConfig)
		h := NewSharedCfgConfigHandler(nil).(*SharedCfgConfigHandler)
		h.Profile("has_role_explicit_mfa")
		if err := h.Config(c); err != nil {
			t.Errorf("Error getting config: %v", err)
		}

		if c.GetRegion() != "us-east-1" || c.GetMfaSerial() != "87654321" {
			t.Errorf("Unexpected result in Config object: %+v", c)
		}
	})

	t.Run("ConfigNil", func(t *testing.T) {
		defer func() {
			if x := recover(); x != nil {
				t.Errorf("Unexpected panic calling Config() with nil option")
			}
		}()
		h := NewSharedCfgConfigHandler(nil)
		if err := h.Config(nil); err != nil {
			t.Errorf("Error getting config: %v", err)
		}
	})
}
