package main

import (
	cfglib "aws-runas/lib/config"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/mmmorris1975/aws-config/config"
	"github.com/mmmorris1975/simple-logger/logger"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

func Example_checkEnvFail() {
	log = logger.NewLogger(os.Stdout, "", 0)
	os.Setenv("AWS_ACCESS_KEY_ID", "AKIAMOCK")
	os.Setenv("AWS_SESSION_TOKEN", "token")
	defer func() { os.Unsetenv("AWS_ACCESS_KEY_ID"); os.Unsetenv("AWS_SESSION_TOKEN") }()

	checkEnv()
	// Output:
	// ERROR detected static access key env var along with session token env var, this is invalid
}

func Example_checkEnvPassEmpty() {
	log = logger.NewLogger(os.Stdout, "", 0)
	os.Setenv("AWS_ACCESS_KEY_ID", "ASIAMOCK")
	defer func() { os.Unsetenv("AWS_ACCESS_KEY_ID"); os.Unsetenv("AWS_SESSION_TOKEN") }()

	checkEnv()
	// Output:
	//
}

func Example_checkEnvPass() {
	log = logger.NewLogger(os.Stdout, "", 0)
	os.Setenv("AWS_ACCESS_KEY_ID", "ASIAMOCK")
	os.Setenv("AWS_SESSION_TOKEN", "token")
	defer func() { os.Unsetenv("AWS_ACCESS_KEY_ID"); os.Unsetenv("AWS_SESSION_TOKEN") }()

	checkEnv()
	// Output:
	// INFO environment variables appear sane
}

func Example_checkRegionFail() {
	log = logger.NewLogger(os.Stdout, "", 0)
	c := cfglib.AwsConfig{AwsConfig: new(config.AwsConfig)}
	checkRegion(&c)
	// Output:
	// ERROR region is not set, it must be specified in the config file or as an environment variable
}

func Example_checkRegionPass() {
	log = logger.NewLogger(os.Stdout, "", 0)
	c := cfglib.AwsConfig{AwsConfig: &config.AwsConfig{Region: "us-east-3"}}
	checkRegion(&c)
	// Output:
	// INFO region is configured in profile or environment variable
}

func Example_printConfig() {
	c := &cfglib.AwsConfig{AwsConfig: new(config.AwsConfig)}
	c.Region = "us-east-3"
	c.SourceProfile = "x"
	c.RoleArn = "my-role"
	c.SessionTokenDuration = 10 * time.Minute
	c.CredentialsDuration = 20 * time.Minute
	c.MfaSerial = "my-mfa"
	c.ExternalId = "abcde"

	printConfig("p", c)
	// Output:
	// PROFILE: p
	// REGION: us-east-3
	// SOURCE PROFILE: x
	// SESSION TOKEN DURATION: 10m0s
	// MFA SERIAL: my-mfa
	// ROLE ARN: my-role
	// EXTERNAL ID: abcde
	// ASSUME ROLE CREDENTIAL DURATION: 20m0s
}

func Example_printConfigSaml() {
	c := &cfglib.AwsConfig{AwsConfig: new(config.AwsConfig)}
	c.Region = "us-east-3"
	c.SourceProfile = "x"
	c.RoleArn = "my-role"
	c.SessionTokenDuration = 10 * time.Minute
	c.CredentialsDuration = 20 * time.Minute
	c.MfaSerial = "my-mfa"
	c.ExternalId = "abcde"
	c.SamlAuthUrl, _ = url.Parse("http://localhost/saml")
	c.SamlUsername = "mock-user"

	printConfig("p", c)
	// Output:
	// PROFILE: p
	// REGION: us-east-3
	// SOURCE PROFILE: x
	// SESSION TOKEN DURATION: 10m0s
	// MFA SERIAL: my-mfa
	// ROLE ARN: my-role
	// EXTERNAL ID: abcde
	// ASSUME ROLE CREDENTIAL DURATION: 20m0s
	// SAML METADATA URL: http://localhost/saml
	// SAML USERNAME: mock-user
	// JUMP ROLE ARN: arn:::::
}

func TestCheckProfile(t *testing.T) {
	log = logger.NewLogger(os.Stdout, "", 0)
	t.Run("empty", func(t *testing.T) {
		p := checkProfile(aws.String(""))
		if p != "default" {
			t.Errorf("did not get default profile")
		}
	})

	t.Run("valid", func(t *testing.T) {
		p := checkProfile(aws.String("x"))
		if p != "x" {
			t.Errorf("did not get input profile")
		}
	})
}

func TestRunDiagnostics(t *testing.T) {
	log = logger.NewLogger(os.Stdout, "", 0)
	os.Setenv(config.ConfigFileEnvVar, ".aws/config")
	defer os.Unsetenv(config.ConfigFileEnvVar)

	t.Run("empty config", func(t *testing.T) {
		c := &cfglib.AwsConfig{AwsConfig: new(config.AwsConfig)}
		if err := runDiagnostics(c); err != nil {
			t.Error(err)
		}
	})

	t.Run("role config", func(t *testing.T) {
		profile = aws.String("my-role")
		c := cfglib.AwsConfig{AwsConfig: &config.AwsConfig{Region: "us-west-3", RoleArn: "my-role"}}
		if err := runDiagnostics(&c); err != nil {
			t.Error(err)
		}
	})
}

func TestCheckTime(t *testing.T) {
	if err := checkTime(); err != nil {
		t.Error(err)
	}
}

func TestCheckCredentialProfile(t *testing.T) {
	log = logger.NewLogger(os.Stdout, "", 0)

	t.Run("bad file", func(t *testing.T) {
		os.Setenv(config.CredentialsFileEnvVar, "not-a.file")
		defer os.Unsetenv(config.CredentialsFileEnvVar)
		if checkCredentialProfile("default") {
			t.Error("unexpected success")
		}
	})

	t.Run("bad profile", func(t *testing.T) {
		os.Setenv(config.CredentialsFileEnvVar, ".aws/credentials")
		defer os.Unsetenv(config.CredentialsFileEnvVar)
		if checkCredentialProfile("bogus") {
			t.Error("unexpected success")
		}
	})

	t.Run("bad profile", func(t *testing.T) {
		os.Setenv(config.CredentialsFileEnvVar, ".aws/credentials")
		defer os.Unsetenv(config.CredentialsFileEnvVar)
		if checkCredentialProfile("incomplete") {
			t.Error("unexpected success")
		}
	})

	t.Run("good", func(t *testing.T) {
		os.Setenv(config.CredentialsFileEnvVar, ".aws/credentials")
		defer os.Unsetenv(config.CredentialsFileEnvVar)
		if !checkCredentialProfile("good") {
			t.Error("unexpected failure")
		}
	})
}

func TestCheckProfileCfg(t *testing.T) {
	t.Run("no profile", func(t *testing.T) {
		checkProfileCfg("", emptyConfig)
	})

	t.Run("iam user", func(t *testing.T) {
		os.Setenv(config.ConfigFileEnvVar, ".aws/config")
		defer os.Unsetenv(config.ConfigFileEnvVar)
		os.Setenv(config.CredentialsFileEnvVar, ".aws/credentials")
		defer os.Unsetenv(config.CredentialsFileEnvVar)

		t.Run("no source", func(t *testing.T) {
			cfg = emptyConfig
			cfg.RoleArn = "aRole"
			checkProfileCfg("diagnostic-bad", cfg)
		})

		t.Run("no role", func(t *testing.T) {
			cfg = emptyConfig
			checkProfileCfg("diagnostic", cfg)
		})

		t.Run("good", func(t *testing.T) {
			cfg = emptyConfig
			cfg.RoleArn = "aRole"
			cfg.SourceProfile = "diagnostic"
			checkProfileCfg("diagnostic-good", cfg)
		})

		t.Run("env", func(t *testing.T) {
			os.Setenv("AWS_ACCESS_KEY_ID", "AAAAA")
			defer os.Unsetenv("AWS_ACCESS_KEY_ID")
			cfg = emptyConfig
			cfg.RoleArn = "aRole"
			cfg.SourceProfile = "diagnostic"
			checkProfileCfg("diagnostic-good", cfg)
		})
	})

	t.Run("saml", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/bad" {
				http.Error(w, "error", http.StatusInternalServerError)
			}
			w.Write([]byte("ok"))
		}))
		defer s.Close()

		t.Run("no role", func(t *testing.T) {
			cfg = emptyConfig
			cfg.SamlAuthUrl, _ = url.Parse(s.URL)
			checkProfileCfg("x", cfg)
		})

		t.Run("bad status", func(t *testing.T) {
			cfg = emptyConfig
			cfg.RoleArn = "role"
			cfg.SamlAuthUrl, _ = url.Parse(s.URL + "/bad")
			checkProfileCfg("x", cfg)
		})

		t.Run("good", func(t *testing.T) {
			cfg = emptyConfig
			cfg.RoleArn = "role"
			cfg.SamlAuthUrl, _ = url.Parse(s.URL)
			checkProfileCfg("x", cfg)
		})
	})
}
