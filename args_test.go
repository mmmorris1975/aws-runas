package main

import (
	"aws-runas/lib/credentials"
	"github.com/alecthomas/kingpin"
	"os"
	"testing"
)

var ev = map[string]string{
	"RUNAS_VERBOSE":             "1",
	"RUNAS_ENV_CREDENTIALS":     "t",
	"RUNAS_SESSION_CREDENTIALS": "true",
	"SESSION_TOKEN_DURATION":    credentials.SessionTokenMaxDuration.String(),
	//"CREDENTIALS_DURATION":      credentials.AssumeRoleMinDuration.String(),
	"MFA_CODE":      "654321",
	"MFA_SERIAL":    "MyMfa",
	"EXTERNAL_ID":   "ExtId",
	"JUMP_ROLE_ARN": "arn:aws:iam::1234567890:role/Jump",
	"SAML_AUTH_URL": "https://example.org/saml",
	"SAML_USERNAME": "mock-user",
	"SAML_PASSWORD": "mock-password",
	"SAML_PROVIDER": "mock-saml",
	"AWS_PROFILE":   "my-profile",
}

func TestArgHandling(t *testing.T) {
	t.Run("no env", func(t *testing.T) {
		// kingpin.Parse() picks up the args used with `go test`, drop one level lower and explicitly set args
		if _, err := kingpin.CommandLine.Parse(nil); err != nil {
			t.Error(err)
			return
		}

		if *verbose || *envFlag || *sesCreds {
			t.Error("unexpected true boolean values")
		}

		if *duration != 0 || *roleDuration != 0 {
			t.Error("unexpected duration values")
		}

		if len(*mfaCode) > 0 || len(*mfaSerial) > 0 || len(*extnId) > 0 {
			t.Error("unexpected mfa or external id")
		}

		if len(*jumpArn) > 0 || *samlUrl != nil || len(*samlUser) > 0 || len(*samlPass) > 0 {
			t.Error("unexpected SAML values")
		}
	})

	// Be careful with this test, setting these env vars may affect the result of other tests when they are run concurrently
	t.Run("env", func(t *testing.T) {
		for k, v := range ev {
			os.Setenv(k, v)
		}

		defer func() {
			for k := range ev {
				os.Unsetenv(k)
			}
		}()

		if _, err := kingpin.CommandLine.Parse(nil); err != nil {
			t.Error(err)
			return
		}

		if !*verbose || !*envFlag || !*sesCreds {
			t.Error("unexpected false boolean values")
		}

		if *duration != credentials.SessionTokenMaxDuration {
			t.Error("unexpected duration values")
		}

		if *mfaCode != ev["MFA_CODE"] || *mfaSerial != ev["MFA_SERIAL"] || *extnId != ev["EXTERNAL_ID"] {
			t.Error("unexpected mfa or external id")
		}

		if *jumpArn != ev["JUMP_ROLE_ARN"] || *samlUser != ev["SAML_USERNAME"] || *samlPass != ev["SAML_PASSWORD"] ||
			(*samlUrl).String() != ev["SAML_AUTH_URL"] || *samlProvider != ev["SAML_PROVIDER"] {
			t.Error("unexpected SAML values")
		}
	})
}
