/*
 * Copyright (c) 2021 Michael Morris. All Rights Reserved.
 *
 * Licensed under the MIT license (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * https://github.com/mmmorris1975/aws-runas/blob/master/LICENSE
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under the License.
 */

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/logging"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/simple-logger/logger"
	"github.com/urfave/cli/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHelpers_installSignalHandler(t *testing.T) {
	installSignalHandler()
}

func TestHelpers_printCredIdentity(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		if err := printCredIdentity(new(mockStsApi)); err != nil {
			t.Error(err)
		}
	})

	t.Run("bad", func(t *testing.T) {
		var api mockStsApi = true
		if err := printCredIdentity(&api); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestHelpers_printCredExpiration(t *testing.T) {
	// if _, err := io.Copy(os.Stdout, os.Stderr); err != nil {
	//	t.Error(err)
	//	return
	// }

	t.Run("never", func(t *testing.T) {
		creds := &credentials.Credentials{Expiration: time.Time{}}
		printCredExpiration(creds)
	})

	t.Run("expired", func(t *testing.T) {
		creds := &credentials.Credentials{Expiration: time.Time{}.Add(1 * time.Nanosecond)}
		printCredExpiration(creds)
	})

	t.Run("valid", func(t *testing.T) {
		creds := &credentials.Credentials{Expiration: time.Now().Add(999999 * time.Hour)}
		printCredExpiration(creds)
	})
}

func TestHelpers_refreshCreds(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		refreshCreds(new(mockAwsClient))
	})

	t.Run("bad", func(t *testing.T) {
		c := mockAwsClient(true)
		refreshCreds(&c)
	})
}

func Test_logFunc(t *testing.T) {
	sb := new(strings.Builder)
	log = logger.NewLogger(sb, "", 0)

	t.Run("debug", func(t *testing.T) {
		log.SetLevel(logger.DEBUG)
		logFunc(logging.Debug, "%s", t.Name())

		if sb.String() != fmt.Sprintf("DEBUG %s\n", t.Name()) {
			t.Error("data mismatch")
		}
		sb.Reset()
	})

	t.Run("warn", func(t *testing.T) {
		log.SetLevel(logger.WARN)
		logFunc(logging.Warn, "%s", t.Name())

		if sb.String() != fmt.Sprintf("WARN %s\n", t.Name()) {
			t.Error("data mismatch")
		}
		sb.Reset()
	})

	t.Run("other", func(t *testing.T) {
		log.SetLevel(logger.DEBUG)
		logFunc("other", "%s", t.Name())

		if sb.String() != fmt.Sprintf("INFO %s\n", t.Name()) {
			t.Error("data mismatch")
		}
		sb.Reset()
	})
}

func TestHelpers_saveStsCredentials(t *testing.T) {
	// helper to create a cli.Context with the write-credentials flag set (or not)
	newCtx := func(t *testing.T, writeFlag bool) *cli.Context {
		t.Helper()
		fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
		fs.Bool(writeCredsFlag.Name, false, "")
		if writeFlag {
			_ = fs.Set(writeCredsFlag.Name, "true")
		}
		return cli.NewContext(App, fs, nil)
	}

	t.Run("flag not set", func(t *testing.T) {
		// When the flag is not set, the credentials file should not be written.
		tf := filepath.Join(t.TempDir(), "credentials")
		os.Setenv("AWS_SHARED_CREDENTIALS_FILE", tf)
		defer os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")

		ctx := newCtx(t, false)
		cred := &credentials.Credentials{AccessKeyId: "AK", SecretAccessKey: "SK"}
		saveStsCredentials(ctx, "myprofile", cred)

		// file should not exist since flag was not set
		if _, err := os.Stat(tf); err == nil {
			t.Error("credentials file should not have been created when flag is not set")
		}
	})

	t.Run("empty profile", func(t *testing.T) {
		tf := filepath.Join(t.TempDir(), "credentials")
		os.Setenv("AWS_SHARED_CREDENTIALS_FILE", tf)
		defer os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")

		ctx := newCtx(t, true)
		cred := &credentials.Credentials{AccessKeyId: "AK", SecretAccessKey: "SK"}
		saveStsCredentials(ctx, "", cred)

		if _, err := os.Stat(tf); err == nil {
			t.Error("credentials file should not have been created with empty profile")
		}
	})

	t.Run("writes credentials", func(t *testing.T) {
		tf := filepath.Join(t.TempDir(), "credentials")
		os.Setenv("AWS_SHARED_CREDENTIALS_FILE", tf)
		defer os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")

		ctx := newCtx(t, true)
		cred := &credentials.Credentials{AccessKeyId: "testAK", SecretAccessKey: "testSK", Token: "testToken"}
		saveStsCredentials(ctx, "myprofile", cred)

		f, err := os.ReadFile(tf)
		if err != nil {
			t.Fatalf("credentials file was not created: %v", err)
		}

		content := string(f)
		if !strings.Contains(content, "[myprofile-awsrunas]") {
			t.Error("credentials file missing expected profile section")
		}
		if !strings.Contains(content, "testAK") {
			t.Error("credentials file missing access key")
		}
		if !strings.Contains(content, "testSK") {
			t.Error("credentials file missing secret key")
		}
		if !strings.Contains(content, "testToken") {
			t.Error("credentials file missing session token")
		}
	})

	t.Run("save error does not panic", func(t *testing.T) {
		// Point to an invalid path so SaveStsCredentials returns an error
		os.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/no/such/dir/credentials")
		defer os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")

		// Capture log output to verify warning is emitted
		sb := new(strings.Builder)
		origLog := log
		log = logger.NewLogger(sb, "", 0)
		log.SetLevel(logger.WARN)
		defer func() { log = origLog }()

		ctx := newCtx(t, true)
		cred := &credentials.Credentials{AccessKeyId: "AK", SecretAccessKey: "SK"}

		// Should not panic
		saveStsCredentials(ctx, "badpath", cred)

		if !strings.Contains(sb.String(), "error writing credentials to file") {
			t.Errorf("expected warning log message, got: %s", sb.String())
		}
	})

	t.Run("nil credentials with flag set", func(t *testing.T) {
		tf := filepath.Join(t.TempDir(), "credentials")
		os.Setenv("AWS_SHARED_CREDENTIALS_FILE", tf)
		defer os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")

		sb := new(strings.Builder)
		origLog := log
		log = logger.NewLogger(sb, "", 0)
		log.SetLevel(logger.WARN)
		defer func() { log = origLog }()

		ctx := newCtx(t, true)
		saveStsCredentials(ctx, "myprofile", nil)

		if !strings.Contains(sb.String(), "error writing credentials to file") {
			t.Errorf("expected warning log for nil creds, got: %s", sb.String())
		}
	})

	t.Run("success log message", func(t *testing.T) {
		tf := filepath.Join(t.TempDir(), "credentials")
		os.Setenv("AWS_SHARED_CREDENTIALS_FILE", tf)
		defer os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")

		sb := new(strings.Builder)
		origLog := log
		log = logger.NewLogger(sb, "", 0)
		log.SetLevel(logger.INFO)
		defer func() { log = origLog }()

		ctx := newCtx(t, true)
		cred := &credentials.Credentials{AccessKeyId: "AK", SecretAccessKey: "SK"}
		saveStsCredentials(ctx, "logtest", cred)

		if !strings.Contains(sb.String(), "Credentials written to AWS credentials file under profile: logtest-awsrunas") {
			t.Errorf("expected info log message, got: %s", sb.String())
		}
	})
}

type mockStsApi bool

func (m *mockStsApi) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if *m {
		return nil, errors.New("failed")
	}

	out := &sts.GetCallerIdentityOutput{
		Account: aws.String("mockAccount"),
		Arn:     aws.String("arn:aws:iam::0123456789:user/Mock"),
		UserId:  aws.String("mockUser"),
	}

	return out, nil
}
