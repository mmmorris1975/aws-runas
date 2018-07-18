package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/mbndr/logo"
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
	defer os.Unsetenv("AWS_CONFIG_FILE")

	cm, err := lib.NewAwsConfigManager(new(lib.ConfigManagerOptions))
	if err != nil {
		t.Errorf("Error from NewAwsConfigManager(): %v", err)
	}

	u := &iam.User{UserName: aws.String("mock-user"), UserId: aws.String("mock-user")}

	t.Run("basic", func(t *testing.T) {
		_, err = awsProfile(cm, "basic", u)
		if err != nil {
			t.Errorf("Unexpected error from awsProfile(): %v", err)
		}
	})
	t.Run("arnValid", func(t *testing.T) {
		_, err = awsProfile(cm, "arn:aws:iam::1234:role/mock", u)
		if err != nil {
			t.Errorf("Unexpected error from awsProfile() with ARN: %v", err)
		}
	})
	t.Run("arnBad", func(t *testing.T) {
		// Anything that fails arn.Parse() gets treated like a profile name
		p, err := awsProfile(cm, "x", u)
		if err == nil {
			t.Errorf("Did not get expected error from awsProfile() with bad profile, got %+v", p)
		}
	})
	t.Run("ArnNotIam", func(t *testing.T) {
		_, err = awsProfile(cm, "arn:aws:s3:::a", u)
		if err == nil {
			t.Errorf("Did not get expected error from awsProfile() with bad ARN")
		}
	})
	t.Run("NameEmpty", func(t *testing.T) {
		os.Setenv("AWS_DEFAULT_PROFILE", "alt_default")
		defer os.Unsetenv("AWS_DEFAULT_PROFILE")
		p, err := awsProfile(cm, "", u)
		if err != nil {
			t.Errorf("Unexpected error from awsProfile() with empty profile: %v", err)
		}
		if p.Name != "alt_default" || p.Region != "us-west-1" || p.MfaSerial != "12345678" {
			t.Errorf("Unexpected result from awsProfile() with empty profile: %+v", err)
		}
	})
}

func TestAssumeRoleInput(t *testing.T) {
	t.Run("Default", func(t *testing.T) {
		i := assumeRoleInput(new(lib.AWSProfile))
		if *i.DurationSeconds != 3600 {
			t.Errorf("Expected default DurationSeconds to be 3600, got %d", *i.DurationSeconds)
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
	// export AWS_DEFAULT_REGION='us-east-1'
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
	// export AWS_DEFAULT_REGION='us-east-1'
	// export AWS_ACCESS_KEY_ID='MockKey'
	// export AWS_SECRET_ACCESS_KEY='MockSecret'
}

func ExamplePrintExpire() {
	p := lib.NewSessionTokenProvider(new(lib.AWSProfile), new(lib.CachedCredentialsProviderOptions))

	// Prints to stderr, so output will be empty
	printExpire(p)
	// Output:
	//
}

func TestCredProvider(t *testing.T) {
	log = logo.NewSimpleLogger(os.Stderr, logo.DEBUG, "TestCredProvider", true)
	t.Run("SessionToken", func(t *testing.T) {
		p := credProvider(new(lib.AWSProfile))
		o := fmt.Sprintf("%T", p)
		if o != "*lib.sessionTokenProvider" {
			t.Errorf("Unexpected type, got %s", o)
		}
	})
	t.Run("AssumeRole", func(t *testing.T) {
		a, _ := arn.Parse("arn:aws:iam::666:role/mock")
		p := credProvider(&lib.AWSProfile{RoleArn: a})
		o := fmt.Sprintf("%T", p)
		if o != "*lib.assumeRoleProvider" {
			t.Errorf("Unexpected type, got %s", o)
		}
	})
}

func TestLookupMfa(t *testing.T) {
	t.Run("StaticSerial", func(t *testing.T) {
		serial := "arn:aws:iam::012345678910:mfa/DEADBEEF"
		mfaArn = aws.String(serial)
		m := lookupMfa(nil)
		if *m != serial {
			t.Errorf("Mismatched static MFA serial: expected %s, got %s", serial, *m)
		}
	})
}

func TestWrapCmd(t *testing.T) {
	t.Run("ExistingBinary", func(t *testing.T) {
		cmd := []string{"true"}
		wrap := wrapCmd(&cmd)
		if (*wrap)[0] != cmd[0] {
			t.Errorf("Unexpected result when wrapping existing binary command")
		}
	})
	// Test fails in circleci because we're running in docker with a shell that isn't supported
	//t.Run("BogusBinary", func(t *testing.T) {
	//	cmd := []string{"not_a_command.123"}
	//	wrap := wrapCmd(&cmd)
	//	if (*wrap)[0] == cmd[0] {
	//		t.Errorf("Expected invalid command to be wrapped, but it wasn't")
	//	}
	//})
}
