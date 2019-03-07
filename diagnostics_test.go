package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/mmmorris1975/aws-runas/lib/config"
	"github.com/mmmorris1975/simple-logger"
	"os"
	"testing"
	"time"
)

func Example_CheckEnvFail() {
	log = simple_logger.NewLogger(os.Stdout, "", 0)
	os.Setenv("AWS_ACCESS_KEY_ID", "AKIAMOCK")
	os.Setenv("AWS_SESSION_TOKEN", "token")
	defer func() { os.Unsetenv("AWS_ACCESS_KEY_ID"); os.Unsetenv("AWS_SESSION_TOKEN") }()

	checkEnv()
	// Output:
	// ERROR detected static access key env var along with session token env var, this is invalid
}

func Example_CheckEnvPass() {
	log = simple_logger.NewLogger(os.Stdout, "", 0)
	os.Setenv("AWS_ACCESS_KEY_ID", "AKIAMOCK")
	defer func() { os.Unsetenv("AWS_ACCESS_KEY_ID"); os.Unsetenv("AWS_SESSION_TOKEN") }()

	checkEnv()
	// Output:
	//
}

func Example_CheckRegionFail() {
	log = simple_logger.NewLogger(os.Stdout, "", 0)
	checkRegion(new(config.AwsConfig))
	// Output:
	// ERROR region is not set, it must be specified in the config file or as an environment variable
}

func Example_CheckRegionPass() {
	log = simple_logger.NewLogger(os.Stdout, "", 0)
	c := config.AwsConfig{Region: "us-east-3"}
	checkRegion(&c)
	// Output:
	//
}

func Example_PrintConfig() {
	c := new(config.AwsConfig)
	c.Region = "us-east-3"
	c.SourceProfile = "x"
	c.RoleArn = "my-role"
	c.RoleDuration = 10 * time.Minute
	c.SessionDuration = 20 * time.Minute
	c.MfaSerial = "my-mfa"
	c.ExternalID = "abcde"

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
		if err := runDiagnostics(new(config.AwsConfig)); err != nil {
			t.Error(err)
		}
	})

	t.Run("role config", func(t *testing.T) {
		p := *profile
		defer func() { profile = &p }()
		profile = aws.String("my-role")
		c := config.AwsConfig{Region: "us-west-3", RoleArn: "my-role"}
		if err := runDiagnostics(&c); err != nil {
			t.Error(err)
		}
	})
}
