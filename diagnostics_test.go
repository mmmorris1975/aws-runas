package main

import (
	cfglib "aws-runas/lib/config"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/mmmorris1975/aws-config/config"
	"github.com/mmmorris1975/simple-logger"
	"os"
	"testing"
	"time"
)

func Example_checkEnvFail() {
	log = simple_logger.NewLogger(os.Stdout, "", 0)
	os.Setenv("AWS_ACCESS_KEY_ID", "AKIAMOCK")
	os.Setenv("AWS_SESSION_TOKEN", "token")
	defer func() { os.Unsetenv("AWS_ACCESS_KEY_ID"); os.Unsetenv("AWS_SESSION_TOKEN") }()

	checkEnv()
	// Output:
	// ERROR detected static access key env var along with session token env var, this is invalid
}

func Example_checkEnvPass() {
	log = simple_logger.NewLogger(os.Stdout, "", 0)
	os.Setenv("AWS_ACCESS_KEY_ID", "AKIAMOCK")
	defer func() { os.Unsetenv("AWS_ACCESS_KEY_ID"); os.Unsetenv("AWS_SESSION_TOKEN") }()

	checkEnv()
	// Output:
	//
}

func Example_checkRegionFail() {
	log = simple_logger.NewLogger(os.Stdout, "", 0)
	checkRegion(new(cfglib.AwsConfig))
	// Output:
	// ERROR region is not set, it must be specified in the config file or as an environment variable
}

func Example_checkRegionPass() {
	log = simple_logger.NewLogger(os.Stdout, "", 0)
	c := cfglib.AwsConfig{AwsConfig: &config.AwsConfig{Region: "us-east-3"}}
	checkRegion(&c)
	// Output:
	// INFO region is configured in profile or environment variable
}

func Example_printConfig() {
	c := new(cfglib.AwsConfig)
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
	// SESSION TOKEN DURATION: 20m0s
	// MFA SERIAL: my-mfa
	// ROLE ARN: my-role
	// EXTERNAL ID: abcde
	// ASSUME ROLE CREDENTIAL DURATION: 10m0s
}

func TestCheckProfile(t *testing.T) {
	log = simple_logger.NewLogger(os.Stdout, "", 0)
	t.Run("empty", func(t *testing.T) {
		p := checkProfile("")
		if p != "default" {
			t.Errorf("did not get default profile")
		}
	})

	t.Run("valid", func(t *testing.T) {
		p := checkProfile("x")
		if p != "x" {
			t.Errorf("did not get input profile")
		}
	})
}

func TestRunDiagnostics(t *testing.T) {
	log = simple_logger.NewLogger(os.Stdout, "", 0)

	t.Run("empty config", func(t *testing.T) {
		if err := runDiagnostics(new(cfglib.AwsConfig)); err != nil {
			t.Error(err)
		}
	})

	t.Run("role config", func(t *testing.T) {
		p := *profile
		defer func() { profile = &p }()
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
