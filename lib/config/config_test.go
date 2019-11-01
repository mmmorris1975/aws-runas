package config

import (
	"github.com/mmmorris1975/aws-config/config"
	"testing"
	"time"
)

func TestWrap(t *testing.T) {
	r, err := config.NewAwsConfigResolver("test/config")
	if err != nil {
		t.Error(err)
		return
	}

	t.Run("default", func(t *testing.T) {
		c, err := r.Resolve()
		if err != nil {
			t.Error(err)
			return
		}

		w, err := Wrap(c)
		if err != nil {
			t.Error(err)
			return
		}

		if w.Profile != config.DefaultProfileName || w.SessionTokenDuration != 20*time.Hour || w.Region != "us-east-1" ||
			w.CredentialsDuration != 1*time.Hour || w.DurationSeconds != int(w.CredentialsDuration.Seconds()) {
			t.Error(err)
		}
	})

	t.Run("iam", func(t *testing.T) {
		c, err := r.Resolve("iam")
		if err != nil {
			t.Error(err)
			return
		}

		w, err := Wrap(c)
		if err != nil {
			t.Error(err)
			return
		}

		if w.Profile != "iam" || w.SessionTokenDuration != 20*time.Hour || w.Region != "us-west-1" ||
			w.CredentialsDuration != 1*time.Hour || w.DurationSeconds != int(w.CredentialsDuration.Seconds()) {
			t.Error(err)
		}
	})

	t.Run("override", func(t *testing.T) {
		c, err := r.Resolve("duration_override")
		if err != nil {
			t.Error(err)
			return
		}

		w, err := Wrap(c)
		if err != nil {
			t.Error(err)
			return
		}

		if w.Profile != "duration_override" || w.SessionTokenDuration != 20*time.Hour || w.Region != "us-east-1" ||
			w.CredentialsDuration != 0 || w.DurationSeconds != 1800 {
			t.Error(err)
		}
	})

	t.Run("saml", func(t *testing.T) {
		c, err := r.Resolve("saml")
		if err != nil {
			t.Error(err)
			return
		}

		w, err := Wrap(c)
		if err != nil {
			t.Error(err)
			return
		}

		if w.Profile != "saml" || w.SessionTokenDuration != 20*time.Hour || w.Region != "eu-west-1" ||
			w.CredentialsDuration != 1*time.Hour || w.DurationSeconds != int(w.CredentialsDuration.Seconds()) ||
			len(w.SamlUsername) > 0 || w.SamlMetadataUrl.Scheme != "https" || w.JumpRoleArn.Resource != "role/Admin" {
			t.Error(err)
		}
	})
}
