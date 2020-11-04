package config

import (
	"github.com/mmmorris1975/aws-runas/shared"
	"reflect"
	"testing"
	"time"
)

func TestNewResolver(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		r := NewResolver(nil, false).WithLogger(new(shared.DefaultLogger))

		if r == nil {
			t.Error("nil resolver")
			return
		}

		if !reflect.DeepEqual(AwsConfig{}, *r.defConfig) || r.config != nil {
			t.Error("config object mismatch")
		}

		if !reflect.DeepEqual(AwsCredentials{}, *r.defCreds) || r.creds != nil {
			t.Error("credential object mismatch")
		}
	})

	t.Run("with default config", func(t *testing.T) {
		cfg := &AwsConfig{Region: "mockRegion"}
		r := NewResolver(nil, false).WithDefaultConfig(cfg)

		if r == nil {
			t.Error("nil resolver")
			return
		}

		if !reflect.DeepEqual(cfg, r.defConfig) {
			t.Error("config object mismatch")
		}
	})

	t.Run("with default credentials", func(t *testing.T) {
		cred := &AwsCredentials{WebIdentityPassword: "mockPassword"}
		r := NewResolver(nil, false).WithDefaultCredentials(cred)

		if r == nil {
			t.Error("nil resolver")
			return
		}

		if !reflect.DeepEqual(cred, r.defCreds) {
			t.Error("credential object mismatch")
		}
	})
}

//nolint:gocyclo
func TestResolver_Config(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		r := NewResolver(new(badLoader), false)
		if _, err := r.Config(""); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("with source profile", func(t *testing.T) {
		r := NewResolver(new(sourceProfileLoader), true)

		cfg, err := r.Config("")
		if err != nil {
			t.Error(err)
			return
		}

		if cfg.SrcProfile != "mock" || cfg.RoleArn != "mockRole" || cfg.ExternalId != "mockExtId" {
			t.Error("data mismatch")
		}

		if cfg.CredentialsDuration != 4*time.Hour || cfg.MfaSerial != "mockMfa" || cfg.Region != "mockRegion" {
			t.Error("source profile attribute mismatch")
		}
	})

	t.Run("no source profile", func(t *testing.T) {
		r := NewResolver(new(sourceProfileLoader), false)

		cfg, err := r.Config("")
		if err != nil {
			t.Error(err)
			return
		}

		if cfg.SrcProfile != "mock" || cfg.RoleArn != "mockRole" || cfg.ExternalId != "mockExtId" {
			t.Error("data mismatch")
		}

		if cfg.CredentialsDuration > 0 || len(cfg.MfaSerial) > 0 || len(cfg.Region) > 0 {
			t.Error("detected source profile attributes")
		}
	})
}

func TestResolver_Credentials(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		r := NewResolver(new(samlLoader), false)

		c, err := r.Credentials("")
		if err != nil {
			t.Error(err)
			return
		}

		if len(c.SamlPassword) < 1 || len(c.WebIdentityPassword) > 0 {
			t.Error("data mismatch")
		}
	})

	t.Run("error", func(t *testing.T) {
		r := NewResolver(new(badLoader), false)
		if _, err := r.Credentials(""); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestResolver_MergeConfig(t *testing.T) {
	dCfg := &AwsConfig{Region: "mockRegion"}

	r := NewResolver(nil, false).WithDefaultConfig(dCfg)
	cfg := r.MergeConfig(&AwsConfig{
		Region:         "otherRegion",
		RoleArn:        "mockArn",
		WebIdentityUrl: "http://localhost/auth",
	})

	if cfg == nil {
		t.Error("nil config")
		return
	}

	if cfg.Region != "otherRegion" || cfg.RoleArn != "mockArn" || cfg.WebIdentityUrl != "http://localhost/auth" {
		t.Error("data mismatch")
	}
}

func TestResolver_MergeCredentials(t *testing.T) {
	dCreds := &AwsCredentials{SamlPassword: "password1"}

	r := NewResolver(nil, false).WithDefaultCredentials(dCreds)
	creds := r.MergeCredentials(&AwsCredentials{
		SamlPassword:        "password2",
		WebIdentityPassword: dCreds.SamlPassword,
	})

	if creds == nil {
		t.Error("nil credentials")
		return
	}

	if creds.SamlPassword != "password2" || creds.WebIdentityPassword != "password1" {
		t.Error("data mismatch")
	}
}
