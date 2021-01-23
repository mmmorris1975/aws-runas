package cli

import (
	"flag"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/urfave/cli/v2"
	"os"
	"path/filepath"
	"testing"
)

func TestPasswordCmd_Action(t *testing.T) {
	configResolver = new(mockConfigResolver)
	cmdlineCreds = &config.AwsCredentials{SamlPassword: "mypassword"}

	t.Run("good", func(t *testing.T) {
		_ = os.Setenv("AWS_PROFILE", "saml")
		_ = os.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials"))
		defer func() {
			os.Unsetenv("AWS_PROFILE")
			os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")
		}()

		ctx := cli.NewContext(App, new(flag.FlagSet), nil)
		if err := passwordCmd.Run(ctx); err != nil {
			t.Error(err)
		}
	})

	t.Run("bad", func(t *testing.T) {
		_ = os.Setenv("AWS_PROFILE", "iam")
		defer os.Unsetenv("AWS_PROFILE")

		ctx := cli.NewContext(App, new(flag.FlagSet), nil)
		if err := passwordCmd.Run(ctx); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestPasswordCmd_validateInput(t *testing.T) {
	t.Run("empty config", func(t *testing.T) {
		if _, err := validateInput(new(config.AwsConfig)); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("saml and web", func(t *testing.T) {
		cfg := &config.AwsConfig{
			SamlUrl:        "http://mock.local/saml",
			WebIdentityUrl: "http://mock.local/oidc",
		}
		if _, err := validateInput(cfg); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("password supplied", func(t *testing.T) {
		cfg := &config.AwsConfig{WebIdentityUrl: "http://mock.local/oidc"}
		cmdlineCreds = &config.AwsCredentials{WebIdentityPassword: "mypassword"}
		defer func() { cmdlineCreds = nil }()

		p, err := validateInput(cfg)
		if err != nil {
			t.Error(err)
		}

		if p != cmdlineCreds.WebIdentityPassword {
			t.Error("password mismatch")
		}
	})

	t.Run("password prompt", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "stdin")
		f, err := os.Create(path)
		if err != nil {
			t.Error(err)
			return
		}
		defer f.Close()

		_, _ = f.WriteString("mypassword\n")

		os.Stdin = f

		cmdlineCreds = new(config.AwsCredentials)
		defer func() { cmdlineCreds = nil }()

		cfg := &config.AwsConfig{SamlUrl: "http://mock.local/saml"}
		if _, err = validateInput(cfg); err != nil {
			t.Error(err)
			return
		}
	})
}

func TestPasswordCmd_updateCreds(t *testing.T) {
	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials"))
	defer os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")

	cfg := &config.AwsConfig{WebIdentityUrl: "http://mock.local/oidc"}
	if err := updateCreds(cfg, "p"); err != nil {
		t.Error(err)
	}
}
