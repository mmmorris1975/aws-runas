package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/mmmorris1975/aws-runas/lib/config"
	credlib "github.com/mmmorris1975/aws-runas/lib/credentials"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	os.Setenv("AWS_CONFIG_FILE", ".aws/config")
	profile = aws.String("x")
	cfg = new(config.AwsConfig)
	usr = new(credlib.AwsIdentity)
	awsSession(*profile, cfg)
	os.Exit(m.Run())
}

func TestWrapCmd(t *testing.T) {
	t.Run("nil cmd", func(t *testing.T) {
		c := wrapCmd(nil)
		if len(*c) > 0 {
			t.Error("should have received empty value")
		}
	})

	t.Run("empty cmd", func(t *testing.T) {
		c := wrapCmd(new([]string))
		if len(*c) > 0 {
			t.Error("should have received empty value")
		}
	})

	t.Run("good", func(t *testing.T) {
		c := wrapCmd(&[]string{"ls"})
		if len(*c) < 1 {
			t.Error("empty command returned")
		}
	})
}

func Example_printCredentials() {
	env := make(map[string]string)
	env["AWS_ACCESS_KEY_ID"] = "AKIAMOCK"
	env["AWS_SECRET_ACCESS_KEY"] = "SecretKey"
	env["AWS_PROFILE"] = "p"
	env["AWS_REGION"] = "us-east-1"

	for k, v := range env {
		os.Setenv(k, v)
		defer os.Unsetenv(k)
	}

	printCredentials()
	// Output:
	// export AWS_REGION='us-east-1'
	// export AWS_ACCESS_KEY_ID='AKIAMOCK'
	// export AWS_SECRET_ACCESS_KEY='SecretKey'
	// export AWSRUNAS_PROFILE='x'
}

// requires setting up credential cache files
//func ExamplePrintCredExpire() {
//
//}

func TestUpdateEnv(t *testing.T) {
	defer os.Unsetenv("AWS_ACCESS_KEY_ID")
	defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	defer os.Unsetenv("AWS_SESSION_TOKEN")
	defer os.Unsetenv("AWS_SECURITY_TOKEN")

	c := credentials.Value{AccessKeyID: "AKIAMOCK", SecretAccessKey: "SecretKey", SessionToken: "SecurityToken"}
	updateEnv(c)

	v, ok := os.LookupEnv("AWS_ACCESS_KEY_ID")
	if !ok || v != c.AccessKeyID {
		t.Error("bad access key")
	}

	v, ok = os.LookupEnv("AWS_SECRET_ACCESS_KEY")
	if !ok || v != c.SecretAccessKey {
		t.Error("bad secret key")
	}

	v, ok = os.LookupEnv("AWS_SESSION_TOKEN")
	if !ok || v != c.SessionToken {
		t.Error("bad session token key")
	}

	v, ok = os.LookupEnv("AWS_SECURITY_TOKEN")
	if !ok || v != c.SessionToken {
		t.Error("bad security token key")
	}
}

func TestHandleUserCreds(t *testing.T) {
	t.Run("role duration > 1 hour", func(t *testing.T) {
		cfg.RoleDuration = 2 * time.Hour
		defer func() { cfg.RoleDuration = credlib.AssumeRoleMinDuration }()
		handleUserCreds()
	})

	t.Run("session creds only", func(t *testing.T) {
		sesCreds = aws.Bool(true)
		defer func() { sesCreds = aws.Bool(false) }()
		handleUserCreds()
	})

	t.Run("assume role creds", func(t *testing.T) {
		cfg.RoleArn = "my-role"
		defer func() { cfg.RoleArn = "" }()
		handleUserCreds()
	})
}

func TestCheckRefresh(t *testing.T) {
	refresh = aws.Bool(true)
	defer func() { refresh = aws.Bool(false); sesCreds = aws.Bool(false) }()
	checkRefresh()
}

func TestAssumeRoleCacheFile(t *testing.T) {
	// returned name will change depending on the machine it runs on
	oldP := *profile
	profile = aws.String("arn:aws:iam::123456789012:role/Administrator")
	cfg.RoleArn = *profile
	defer func() { profile = &oldP; cfg.RoleArn = "" }()

	f := assumeRoleCacheFile()
	if len(f) < 1 {
		t.Error("empty role cache name")
	}

	if !strings.HasSuffix(f, fmt.Sprintf("%s_%s", assumeRoleCachePrefix, "123456789012-Administrator")) {
		t.Error("bad role cache name")
	}
}

func TestSessionTokenCacheFile(t *testing.T) {
	// returned name will change depending on the machine it runs on
	t.Run("profile", func(t *testing.T) {
		f := sessionTokenCacheFile()
		if len(f) < 1 {
			t.Error("empty session cache name")
		}

		if !strings.HasSuffix(f, fmt.Sprintf("%s_%s", sessionTokenCachePrefix, "x")) {
			t.Error("bad session cache name")
		}
	})
}

func TestAssumeRoleCredentials(t *testing.T) {
	c := assumeRoleCredentials(nil)
	if c == nil {
		t.Error("nil role credentials object")
	}
}

func TestAssumeRoleCredentialsMfa(t *testing.T) {
	mfaCode = aws.String("000000")
	defer func() { mfaCode = nil }()

	c := assumeRoleCredentials(nil)
	if c == nil {
		t.Error("nil role credentials object")
	}
}

func TestSessionTokenCredentials(t *testing.T) {
	c := sessionTokenCredentials()
	if c == nil {
		t.Error("nil session object")
	}
}

func TestSessionTokenCredentialsMfa(t *testing.T) {
	mfaCode = aws.String("111111")
	defer func() { mfaCode = nil }()

	c := sessionTokenCredentials()
	if c == nil {
		t.Error("nil session object")
	}
}

func TestResolveConfig(t *testing.T) {
	d := 30 * time.Minute
	duration = &d
	resolveConfig()
	if cfg == nil {
		t.Error("nil config object")
	}

	if cfg.SessionDuration != 30*time.Minute {
		t.Error("session duration mismatch")
	}
}
