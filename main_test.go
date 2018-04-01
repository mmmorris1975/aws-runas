package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/mmmorris1975/aws-runas/lib"
	"os"
	"runtime"
	"testing"
	"time"
)

func init() {
	os.Unsetenv("AWS_PROFILE")
	os.Unsetenv("AWS_DEFAULT_PROFILE")
	os.Unsetenv("AWS_REGION")
}

func TestAwsProfile(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", "lib/config/test/aws.cfg")
	cm, err := lib.NewAwsConfigManager(new(lib.ConfigManagerOptions))
	if err != nil {
		t.Errorf("Error from NewAwsConfigManager(): %v", err)
	}

	t.Run("basic", func(t *testing.T) {
		_, err = awsProfile(cm, "basic")
		if err != nil {
			t.Errorf("Unexpected error from awsProfile(): %v", err)
		}
	})
	t.Run("arn", func(t *testing.T) {
		_, err = awsProfile(cm, "arn:aws:iam::1234:role/mock")
		if err != nil {
			t.Errorf("Unexpected error from awsProfile() with ARN: %v", err)
		}
	})
	t.Run("badArn", func(t *testing.T) {
		p, err := awsProfile(cm, "x")
		if err == nil {
			t.Errorf("Did not get expected error from awsProfile() with bad profile, got %+v", p)
		}
	})
	t.Run("invalidArn", func(t *testing.T) {
		_, err = awsProfile(cm, "arn:aws:s3:::a")
		if err == nil {
			t.Errorf("Did not get expected error from awsProfile() with bad ARN")
		}
	})

	os.Unsetenv("AWS_CONFIG_FILE")
}

func TestAssumeRoleInput(t *testing.T) {
	t.Run("Default", func(t *testing.T) {
		i := assumeRoleInput(new(lib.AWSProfile))
		if *i.DurationSeconds != 0 {
			t.Errorf("Expected default DurationSeconds to be 0, got %d", *i.DurationSeconds)
		}
	})
	t.Run("NilProfile", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic when using nil AWSProfile")
			}
		}()
		assumeRoleInput(nil)
	})
}

func ExampleAssumeRoleInput() {
	a, err := arn.Parse("arn:aws:iam::666:role/mock")
	if err != nil {
		panic(err)
	}
	p := lib.AWSProfile{
		RoleArn:         a,
		RoleSessionName: "mock-session",
		ExternalId:      "mock-ext-id",
		CredDuration:    1 * time.Hour,
	}

	i := assumeRoleInput(&p)
	fmt.Println(*i.RoleArn)
	fmt.Println(*i.RoleSessionName)
	fmt.Println(*i.ExternalId)
	fmt.Println(*i.DurationSeconds)
	// Output:
	// arn:aws:iam::666:role/mock
	// mock-session
	// mock-ext-id
	// 3600
}

func ExamplePrintCredentials() {
	switch runtime.GOOS {
	case "windows":
		return
	}

	p := lib.AWSProfile{Region: "us-east-1", Name: "mock"}
	c := credentials.Value{
		AccessKeyID:     "MockKey",
		SecretAccessKey: "MockSecret",
		SessionToken:    "MockSession",
	}
	updateEnv(c, p.Region)
	printCredentials()
	// Output:
	// export AWS_REGION='us-east-1'
	// export AWS_ACCESS_KEY_ID='MockKey'
	// export AWS_SECRET_ACCESS_KEY='MockSecret'
	// export AWS_SESSION_TOKEN='MockSession'
	// export AWS_SECURITY_TOKEN='MockSession'
}

func ExamplePrintCredentialsNoSession() {
	os.Setenv("AWS_SESSION_TOKEN", "bogus")
	defer os.Unsetenv("AWS_SESSION_TOKEN")

	p := lib.AWSProfile{Region: "us-east-1", Name: "mock"}
	c := credentials.Value{
		AccessKeyID:     "MockKey",
		SecretAccessKey: "MockSecret",
	}
	updateEnv(c, p.Region)
	printCredentials()
	// Output:
	// export AWS_REGION='us-east-1'
	// export AWS_ACCESS_KEY_ID='MockKey'
	// export AWS_SECRET_ACCESS_KEY='MockSecret'
}
