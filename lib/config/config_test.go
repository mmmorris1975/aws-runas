package config

import (
	"github.com/mmmorris1975/aws-config/config"
	"github.com/mmmorris1975/aws-runas/lib/credentials"
	"os"
	"testing"
	"time"
)

func TestNewConfigResolver(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		r, err := NewConfigResolver(nil)
		if err != nil {
			t.Error(err)
			return
		}

		if r == nil {
			t.Error("unexpected nil resolver")
			return
		}

		if r.file == nil || len(r.file.Path) < 1 {
			t.Error("config file not set")
		}
	})

	t.Run("good", func(t *testing.T) {
		r, err := NewConfigResolver(&AwsConfig{Region: "us-west-2"})
		if err != nil {
			t.Error(err)
			return
		}

		if r.userConfig.Region != "us-west-2" {
			t.Error("unexpected region")
		}
	})

	t.Run("config file env var", func(t *testing.T) {
		os.Setenv(config.ConfigFileEnvVar, "test/config")
		defer os.Unsetenv(config.ConfigFileEnvVar)

		r, err := NewConfigResolver(nil)
		if err != nil {
			t.Error(err)
			return
		}

		if r.file == nil || r.file.Path != "test/config" {
			t.Error("bad file name")
		}
	})
}

func TestConfigResolver_ResolveConfig(t *testing.T) {
	os.Setenv(config.ConfigFileEnvVar, "test/config")
	defer os.Unsetenv(config.ConfigFileEnvVar)

	t.Run("default only", func(t *testing.T) {
		r, err := NewConfigResolver(nil)
		if err != nil {
			t.Error(err)
			return
		}

		c, err := r.ResolveConfig("")
		if err != nil {
			t.Error(err)
			return
		}

		if c.Region != "us-west-1" {
			t.Error("unexpected region")
		}

		if len(c.MfaSerial) > 0 {
			t.Error("unexpected mfa serial")
		}

		if len(c.RoleArn) > 0 {
			t.Error("unexpected role value")
		}

		if c.SessionDuration != credentials.SessionTokenDefaultDuration {
			t.Error("unexpected session duration")
		}

		if c.RoleDuration != credentials.AssumeRoleDefaultDuration {
			t.Error("unexpected role duration")
		}
	})

	t.Run("source", func(t *testing.T) {
		r, err := NewConfigResolver(nil)
		if err != nil {
			t.Error(err)
			return
		}

		c, err := r.ResolveConfig("source")
		if err != nil {
			t.Error(err)
			return
		}

		if c.Region != "us-east-1" {
			t.Error("unexpected region")
		}

		if c.MfaSerial != "ABCDEFG" {
			t.Error("unexpected mfa serial value")
		}

		if len(c.RoleArn) > 0 {
			t.Error("unexpected role value")
		}

		if c.SessionDuration == 0 {
			t.Error("unexpected session duration")
		}

		if c.RoleDuration != credentials.AssumeRoleDefaultDuration {
			t.Error("unexpected role duration")
		}
	})

	t.Run("role default source", func(t *testing.T) {
		r, err := NewConfigResolver(nil)
		if err != nil {
			t.Error(err)
			return
		}

		c, err := r.ResolveConfig("role1")
		if err != nil {
			t.Error(err)
			return
		}

		if c.Region != "us-west-1" {
			t.Error("unexpected region")
		}

		if len(c.MfaSerial) > 0 {
			t.Error("unexpected mfa serial")
		}

		if c.RoleArn != "role1" {
			t.Error("unexpected role value")
		}

		if c.SessionDuration != credentials.SessionTokenDefaultDuration {
			t.Error("unexpected session duration")
		}

		if c.RoleDuration != credentials.AssumeRoleDefaultDuration {
			t.Error("unexpected role duration")
		}
	})

	t.Run("role non-default source", func(t *testing.T) {
		r, err := NewConfigResolver(nil)
		if err != nil {
			t.Error(err)
			return
		}

		c, err := r.ResolveConfig("role2")
		if err != nil {
			t.Error(err)
			return
		}

		if c.Region != "us-east-1" {
			t.Error("unexpected region")
		}

		if c.MfaSerial != "ABCDEFG" {
			t.Error("unexpected mfa serial value")
		}

		if c.RoleArn != "role2" {
			t.Error("unexpected role value")
		}

		if c.SessionDuration == 0 {
			t.Error("unexpected session duration")
		}

		if c.RoleDuration != credentials.AssumeRoleDefaultDuration {
			t.Error("unexpected role duration")
		}
	})

	t.Run("role bad source", func(t *testing.T) {
		r, err := NewConfigResolver(nil)
		if err != nil {
			t.Error(err)
			return
		}

		c, err := r.ResolveConfig("role3")
		if err != nil {
			t.Error(err)
			return
		}

		if c.SourceProfile != "other" {
			t.Error("source profile mismatch")
		}
	})

	t.Run("arn", func(t *testing.T) {
		os.Setenv(MfaSerialEnvVar, "654321")
		defer os.Unsetenv(MfaSerialEnvVar)

		arn := "arn:aws:iam::0123456789012:role/Admin"

		r, err := NewConfigResolver(nil)
		if err != nil {
			t.Error(err)
			return
		}

		c, err := r.ResolveConfig(arn)
		if err != nil {
			t.Error(err)
			return
		}

		if c.Region != "us-west-1" {
			t.Error("unexpected region")
		}

		if c.RoleArn != arn {
			t.Error("bad role value")
		}

		if c.MfaSerial != "654321" {
			t.Error("bad mfa value")
		}
	})

	t.Run("bad arn", func(t *testing.T) {

		arn := "arn:aws:iam::0123456789012:user/Admin"

		r, err := NewConfigResolver(nil)
		if err != nil {
			t.Error(err)
			return
		}

		_, err = r.ResolveConfig(arn)
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestConfigResolver_ResolveDefaultConfig(t *testing.T) {
	os.Setenv(config.ConfigFileEnvVar, "test/config")
	defer os.Unsetenv(config.ConfigFileEnvVar)

	r, err := NewConfigResolver(nil)
	if err != nil {
		t.Error(err)
		return
	}

	t.Run("default", func(t *testing.T) {
		c, err := r.ResolveDefaultConfig()
		if err != nil {
			t.Error(err)
			return
		}

		if c.Region != "us-west-1" {
			t.Error("unexpected region")
		}

		if len(c.MfaSerial) > 0 {
			t.Error("mfa serial was set for default profile")
		}
	})

	t.Run("good env var", func(t *testing.T) {
		os.Setenv(DefaultProfileEnvVar, "source")
		defer os.Unsetenv(DefaultProfileEnvVar)

		c, err := r.ResolveDefaultConfig()
		if err != nil {
			t.Error(err)
			return
		}

		if c.Region != "us-east-1" {
			t.Error("unexpected region")
		}

		if len(c.MfaSerial) > 0 {
			t.Error("mfa serial was set for default profile")
		}

		if c.SessionDuration == 0 {
			t.Error("bad session duration")
		}
	})

	t.Run("bad env var", func(t *testing.T) {
		os.Setenv(DefaultProfileEnvVar, "bad")
		defer os.Unsetenv(DefaultProfileEnvVar)

		_, err := r.ResolveDefaultConfig()
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestConfigResolver_ResolveProfileConfig(t *testing.T) {
	os.Setenv(config.ConfigFileEnvVar, "test/config")
	defer os.Unsetenv(config.ConfigFileEnvVar)

	r, err := NewConfigResolver(nil)
	if err != nil {
		t.Error(err)
		return
	}

	t.Run("profile exists", func(t *testing.T) {
		c, err := r.ResolveProfileConfig("role1")
		if err != nil {
			t.Error(err)
			return
		}

		if c.RoleArn != "role1" {
			t.Error("role mismatch")
		}
	})

	t.Run("empty profile", func(t *testing.T) {
		// Will look up default profile
		_, err := r.ResolveProfileConfig("")
		if err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("bad profile", func(t *testing.T) {
		_, err := r.ResolveProfileConfig("bogus")
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestConfigResolver_ResolveEnvConfig(t *testing.T) {
	env := make(map[string]string)
	env[RegionEnvVar] = "us-east-2"
	env[ProfileEnvVar] = "profile"
	env[SessionDurationEnvVar] = "1m"
	env[config.CredentialsFileEnvVar] = "test/config"

	for k, v := range env {
		os.Setenv(k, v)
		defer os.Unsetenv(k)
	}

	r, err := NewConfigResolver(nil)
	if err != nil {
		t.Error(err)
		return
	}

	t.Run("good", func(t *testing.T) {
		c, err := r.ResolveEnvConfig()
		if err != nil {
			t.Error(err)
			return
		}

		if c.Region != env[RegionEnvVar] {
			t.Error("bad region")
		}

		if c.SessionDuration != 1*time.Minute {
			t.Error("bad session duration")
		}

		if len(c.RoleArn) > 0 {
			t.Error("unexpected role arn")
		}
	})

	t.Run("bad duration", func(t *testing.T) {
		os.Setenv(RoleDurationEnvVar, "ab")
		defer os.Unsetenv(RoleDurationEnvVar)

		_, err := r.ResolveEnvConfig()
		if err == nil {
			t.Error("did not see expected error")
			return
		}
	})
}

func TestMergeConfig(t *testing.T) {
	t.Run("all nil", func(t *testing.T) {
		c := MergeConfig(nil)
		if c == nil {
			t.Error("nil config")
			return
		}

		if len(c.Region) > 0 {
			t.Error("unexpected region value")
		}

		if len(c.RoleArn) > 0 {
			t.Error("unexpected role arn")
		}

		if len(c.MfaSerial) > 0 {
			t.Error("unexpected mfa serial")
		}

		if len(c.ExternalID) > 0 {
			t.Error("unexpected external id")
		}

		if c.SessionDuration > 0 {
			t.Error("unexpeted session duration")
		}

		if c.RoleDuration > 0 {
			t.Error("unexpected role duration")
		}
	})

	t.Run("good", func(t *testing.T) {
		c := MergeConfig(
			nil,
			&AwsConfig{Region: "us-east-1"},
			&AwsConfig{MfaSerial: "123456"},
			nil,
			&AwsConfig{Region: "us-east-2", RoleArn: "my-role"})

		if c == nil {
			t.Error("unexpected nil config")
			return
		}

		if c.Region != "us-east-2" {
			t.Error("bad region")
		}

		if c.MfaSerial != "123456" {
			t.Error("bad mfa serial")
		}

		if c.RoleArn != "my-role" {
			t.Error("bad role")
		}
	})
}
