package main

import (
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/mmmorris1975/aws-runas/lib"
	"os"
	"runtime"
	"testing"
)

func TestAwsProfile(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", "lib/test/aws.cfg")
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
		_, err = awsProfile(cm, "x")
		if err == nil {
			t.Errorf("Did not get expected error from awsProfile() with bad ARN")
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
	printCredentials(&p, c)
	// Output:
	// export AWS_REGION='us-east-1'
	// export AWS_PROFILE='mock'
	// export AWS_ACCESS_KEY_ID='MockKey'
	// export AWS_SECRET_ACCESS_KEY='MockSecret'
	// export AWS_SESSION_TOKEN='MockSession'
	// export AWS_SECURITY_TOKEN='MockSession'
}
