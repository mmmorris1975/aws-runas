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
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/credentials"
	"os"
	"strings"
	"testing"
)

func TestApp_buildEnv(t *testing.T) {
	t.Run("with region", func(t *testing.T) {
		env := buildEnv("r", new(credentials.Credentials))
		if len(env["AWS_REGION"]) < 1 || len(env["AWS_DEFAULT_REGION"]) < 1 {
			t.Error("region was not set")
		}
	})

	t.Run("creds with token", func(t *testing.T) {
		cred := &credentials.Credentials{
			AccessKeyId:     "mockAK",
			SecretAccessKey: "mockSK",
			Token:           "mockToken",
		}

		env := buildEnv("", cred)
		if len(env["AWS_ACCESS_KEY_ID"]) < 1 || len(env["AWS_SECRET_ACCESS_KEY"]) < 1 ||
			len(env["AWS_SESSION_TOKEN"]) < 1 || len(env["AWS_SECURITY_TOKEN"]) < 1 {
			t.Error("invalid credentials in env")
		}
	})

	t.Run("creds no token", func(t *testing.T) {
		_ = os.Setenv("AWS_SESSION_TOKEN", "x")

		cred := &credentials.Credentials{
			AccessKeyId:     "mockAK",
			SecretAccessKey: "mockSK",
		}

		buildEnv("", cred)

		if _, ok := os.LookupEnv("AWS_SESSION_TOKEN"); ok {
			t.Error("session token env var was set")
		}
	})
}

func TestApp_runEcsSvc(t *testing.T) {
	curEnv := os.Environ()
	defer func() {
		os.Clearenv()
		for _, e := range curEnv {
			parts := strings.Split(e, `=`)
			_ = os.Setenv(parts[0], parts[1])
		}
	}()

	_ = os.Setenv("AWS_ACCESS_KEY_ID", "mock")
	_ = os.Setenv("AWS_SHARED_CREDENTIALS_FILE", "x")

	if _, err := runEcsSvc(nil, &config.AwsConfig{ProfileName: "mock"}); err != nil {
		t.Error(err)
		return
	}

	if _, ok := os.LookupEnv("AWS_ACCESS_KEY_ID"); ok {
		t.Error("invalid environment")
	}

	if v := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); v != os.DevNull {
		t.Error("invalid environment")
	}

	if v, ok := os.LookupEnv("AWS_CONTAINER_CREDENTIALS_FULL_URI"); !ok {
		t.Error("container cred uri env var was not set")
	} else if !strings.HasPrefix(v, "http") {
		t.Error("invalid container cred uri env var")
	}
}

func TestApp_wrapCmd(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		if len(wrapCmd(nil)) > 0 {
			t.Error("wrapped command had value")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if len(wrapCmd([]string{})) > 0 {
			t.Error("wrapped command had value")
		}
	})

	t.Run("with shell", func(t *testing.T) {
		_, shellSet := os.LookupEnv("SHELL")
		if !shellSet {
			os.Setenv("SHELL", "/bin/bash")
			defer os.Unsetenv("SHELL")
		}

		if len(wrapCmd([]string{"not_a_command", "-v", "arg"})) != 4 {
			t.Error("command was not wrapped")
		}
	})

	t.Run("no shell", func(t *testing.T) {
		currShell, shellSet := os.LookupEnv("SHELL")
		if shellSet {
			_ = os.Unsetenv("SHELL")
			defer os.Setenv("SHELL", currShell)
		}

		if len(wrapCmd([]string{"not_a_command", "-v", "arg"})) != 3 {
			t.Error("command was wrapped")
		}
	})
}

func TestApp_guessNArgs(t *testing.T) {
	t.Run("with env", func(t *testing.T) {
		_ = os.Setenv("AWS_PROFILE", "mock")
		defer os.Unsetenv("AWS_PROFILE")

		if guessNArgs(2) != 3 {
			t.Error("NArgs mismatch")
		}
	})

	t.Run("without env", func(t *testing.T) {
		if guessNArgs(2) != 2 {
			t.Error("NArgs mismatch")
		}
	})
}

func ExampleApp_printCreds_profile() {
	_ = os.Setenv("AWSRUNAS_PROFILE", "p")
	defer os.Unsetenv("AWSRUNAS_PROFILE")

	m := map[string]string{
		"E1": "V1",
		"E2": "V2",
	}

	printCreds(m)
	// Unordered output:
	//
	// export E1='V1'
	// export E2='V2'
	// export AWSRUNAS_PROFILE='p'
}

func ExampleApp_printCreds_no_profile() {
	m := map[string]string{
		"E1": "V1",
		"E2": "V2",
	}

	printCreds(m)
	// Unordered output:
	//
	// export E1='V1'
	// export E2='V2'
}
