package cli

import (
	"flag"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/urfave/cli/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDiagnoseCmd_Action(t *testing.T) {
	configResolver = new(mockConfigResolver)
	ctx := cli.NewContext(App, new(flag.FlagSet), nil)

	if err := diagCmd.Run(ctx); err != nil {
		t.Error(err)
	}
}

func TestDiagnoseCmd_checkEnv(t *testing.T) {
	t.Run("env creds", func(t *testing.T) {
		_ = os.Setenv("AWS_ACCESS_KEY_ID", "AKIAmock")
		_ = os.Setenv("AWS_SESSION_TOKEN", "t")
		defer func() {
			_ = os.Unsetenv("AWS_ACCESS_KEY_ID")
			_ = os.Unsetenv("AWS_SESSION_TOKEN")
		}()

		checkEnv()
	})

	t.Run("clean env", func(t *testing.T) {
		_ = os.Setenv("AWS_ACCESS_KEY_ID", "ASIAmock")
		_ = os.Setenv("AWS_SESSION_TOKEN", "t")
		defer func() {
			_ = os.Unsetenv("AWS_ACCESS_KEY_ID")
			_ = os.Unsetenv("AWS_SESSION_TOKEN")
		}()

		checkEnv()
	})
}

func TestDiagnoseCmd_checkRegion(t *testing.T) {
	t.Run("set", func(t *testing.T) {
		checkRegion("r")
	})

	t.Run("unset", func(t *testing.T) {
		checkRegion("")
	})
}

func TestDiagnoseCmd_checkProfileCfg(t *testing.T) {
	t.Run("saml and oidc", func(t *testing.T) {
		cfg := &config.AwsConfig{
			SamlUrl:        "http://mock.local/saml",
			WebIdentityUrl: "http://mock.local/oidc",
		}
		checkProfileCfg(cfg)
	})

	// WARNING: testing a config with a saml or oidc url will cause a http request to the endpoint
	t.Run("saml", func(t *testing.T) {
		s := httptest.NewServer(http.NotFoundHandler())
		defer s.Close()

		t.Run("with role", func(t *testing.T) {
			cfg := &config.AwsConfig{
				RoleArn:     "myrole",
				SamlUrl:     s.URL,
				ProfileName: "mock",
			}
			checkProfileCfg(cfg)
		})

		t.Run("without role", func(t *testing.T) {
			cfg := &config.AwsConfig{
				SamlUrl:     s.URL,
				ProfileName: "mock",
			}
			checkProfileCfg(cfg)
		})
	})

	t.Run("oidc", func(t *testing.T) {
		s := httptest.NewServer(http.NotFoundHandler())
		defer s.Close()

		t.Run("valid client", func(t *testing.T) {
			cfg := &config.AwsConfig{
				ProfileName:            "mock",
				RoleArn:                "myrole",
				WebIdentityUrl:         s.URL,
				WebIdentityClientId:    "mockId",
				WebIdentityRedirectUri: "app:/callback",
			}
			checkProfileCfg(cfg)
		})

		t.Run("invalid client", func(t *testing.T) {
			cfg := &config.AwsConfig{
				RoleArn:        "myrole",
				WebIdentityUrl: s.URL,
				ProfileName:    "mock",
			}
			checkProfileCfg(cfg)
		})
	})

	t.Run("iam role", func(t *testing.T) {
		t.Run("with source profile", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credentials")
			f, err := os.Create(path)
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = f.WriteString("[default]")
			_ = f.Close()

			_ = os.Setenv("AWS_SHARED_CREDENTIALS_FILE", path)
			defer os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")

			// we can't set the private sourceProfile field, so this won't work as expected
			cfg := &config.AwsConfig{RoleArn: "role", ProfileName: "p", SrcProfile: "default"}
			checkProfileCfg(cfg)
		})

		t.Run("missing source profile", func(t *testing.T) {
			cfg := &config.AwsConfig{RoleArn: "role", ProfileName: "p"}
			checkProfileCfg(cfg)
		})
	})

	t.Run("iam session", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "credentials")
		f, err := os.Create(path)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = f.WriteString("[default]\naws_access_key_id=k\naws_secret_access_key=s\n")
		_ = f.Close()

		cfg := &config.AwsConfig{ProfileName: "default"}

		t.Run("file creds", func(t *testing.T) {
			checkProfileCfg(cfg)
		})

		t.Run("file and env creds", func(t *testing.T) {
			_ = os.Setenv("AWS_ACCESS_KEY_ID", "ak")
			defer os.Unsetenv("AWS_ACCESS_KEY_ID")
			checkProfileCfg(cfg)
		})
	})
}

func TestDiagnoseCmd_checkCredentialProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	f, err := os.Create(path)
	if err != nil {
		t.Error(err)
		return
	}
	_, _ = f.WriteString(`[default]

[creds]
aws_access_key_id = key
aws_secret_access_key = secret
`)
	_ = f.Close()

	t.Run("bad file", func(t *testing.T) {
		os.Setenv("AWS_SHARED_CREDENTIALS_FILE", "not a file")
		if checkCredentialProfile("missing") {
			t.Error("loaded an invalid file")
		}
	})

	_ = os.Setenv("AWS_SHARED_CREDENTIALS_FILE", path)
	defer os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")

	t.Run("bad section", func(t *testing.T) {
		if checkCredentialProfile("missing") {
			t.Error("loaded an invalid section")
		}
	})

	t.Run("bad creds", func(t *testing.T) {
		if checkCredentialProfile("default") {
			t.Error("loaded a section without credentials")
		}
	})

	t.Run("good", func(t *testing.T) {
		if !checkCredentialProfile("creds") {
			t.Error("didn't load a section with credentials")
		}
	})
}

func TestDiagnoseCmd_checkTime(t *testing.T) {
	// not sure what do do after this ... guess we do it for the coverage
	checkTime()
}

func Example_printConfig_no_external() {
	cfg := &config.AwsConfig{
		Region:      "r",
		RoleArn:     "myrole",
		ProfileName: "p",
		SrcProfile:  "s",
		MfaSerial:   "mfa",
		ExternalId:  "e",
	}

	printConfig(cfg)
	// Output:
	//
	// PROFILE: p
	// REGION: r
	// SOURCE PROFILE: s
	// SESSION TOKEN DURATION: 0s
	// MFA SERIAL: mfa
	// ROLE ARN: myrole
	// EXTERNAL ID: e
	// ASSUME ROLE CREDENTIAL DURATION: 0s
}

func Example_printConfig_saml() {
	cfg := &config.AwsConfig{
		ExternalId:      "e",
		MfaSerial:       "mfa",
		MfaCode:         "c",
		Region:          "r",
		RoleArn:         "role",
		RoleSessionName: "name",
		SrcProfile:      "s",
		JumpRoleArn:     "j",
		SamlUrl:         "saml://u",
		SamlUsername:    "user",
		SamlProvider:    "mock",
		ProfileName:     "p",
	}

	printConfig(cfg)
	// Output:
	//
	// PROFILE: p
	// REGION: r
	// SOURCE PROFILE: s
	// SESSION TOKEN DURATION: 0s
	// MFA SERIAL: mfa
	// ROLE ARN: role
	// EXTERNAL ID: e
	// ASSUME ROLE CREDENTIAL DURATION: 0s
	// SAML ENDPOINT URL: saml://u
	// SAML USERNAME: user
	// JUMP ROLE ARN: j
}

func Example_printConfig_oidc() {
	cfg := &config.AwsConfig{
		ExternalId:             "e",
		MfaSerial:              "mfa",
		MfaCode:                "c",
		Region:                 "r",
		RoleArn:                "role",
		RoleSessionName:        "name",
		SrcProfile:             "s",
		JumpRoleArn:            "j",
		WebIdentityUrl:         "oidc://u",
		WebIdentityUsername:    "user",
		WebIdentityProvider:    "mock",
		WebIdentityClientId:    "id",
		WebIdentityRedirectUri: "app:/callback",
		ProfileName:            "p",
	}

	printConfig(cfg)
	// Output:
	//
	// PROFILE: p
	// REGION: r
	// SOURCE PROFILE: s
	// SESSION TOKEN DURATION: 0s
	// MFA SERIAL: mfa
	// ROLE ARN: role
	// EXTERNAL ID: e
	// ASSUME ROLE CREDENTIAL DURATION: 0s
	// WEB IDENTITY ENDPOINT URL: oidc://u
	// WEB IDENTITY CLIENT ID: id
	// WEB IDENTITY REDIRECT URI: app:/callback
	// WEB IDENTITY USERNAME: user
	// JUMP ROLE ARN: j
}
