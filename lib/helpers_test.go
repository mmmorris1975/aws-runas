package lib

import (
	"github.com/aws/aws-sdk-go/aws/defaults"
	"os"
	"testing"
)

func TestAwsConfigFileDefault(t *testing.T) {
	os.Unsetenv("AWS_CONFIG_FILE")
	c := AwsConfigFile()
	exp := defaults.SharedConfigFilename()

	if c != exp {
		t.Errorf("Expected %s, Got %s", exp, c)
	}
}

func TestAwsConfigFileEnv(t *testing.T) {
	exp := "my_aws_config"
	os.Setenv("AWS_CONFIG_FILE", exp)
	c := AwsConfigFile()

	if c != exp {
		t.Errorf("Expected %s, Got %s", exp, c)
	}
}

func TestAwsSessionProfile(t *testing.T) {
	p := "my_profile"
	AwsSession(p)
}

func TestAwsSessionNoProfile(t *testing.T) {
	AwsSession("")
}

func ExamplePromptForMfa() {
	PromptForMfa()
	// Output:
	// Enter MFA Code:
}

func TestVersionCheck(t *testing.T) {
	if err := VersionCheck(""); err != nil {
		t.Errorf("Unexpected error from VersionCheck: %v", err)
	}
}
