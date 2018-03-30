package main

import (
	"github.com/mmmorris1975/aws-runas/lib"
	"os"
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
