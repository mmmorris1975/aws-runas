package main

import (
	"aws-runas/lib/config"
	"aws-runas/lib/identity"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	cfglib "github.com/mmmorris1975/aws-config/config"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestResolveConfig(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", ".aws/config")
	defer os.Unsetenv("AWS_CONFIG_FILE")

	t.Run("default", func(t *testing.T) {
		profile = coalesce(nil, nil, nil, aws.String("default"))

		if err := resolveConfig(); err != nil {
			t.Error(err)
			return
		}

		if cfg.Region != "us-east-2" || cfg.CredentialsDuration < 1 || cfg.DurationSeconds != 3601 {
			t.Error("data mismatch")
		}
	})

	t.Run("good arn profile", func(t *testing.T) {
		profile = aws.String("arn:aws:iam::1234567890:role/Admin")

		if err := resolveConfig(); err != nil {
			t.Error(err)
			return
		}

		if cfg.Region != "us-east-2" || cfg.CredentialsDuration < 1 || cfg.DurationSeconds != 3601 {
			t.Error("data mismatch")
		}
	})

	t.Run("bad arn profile", func(t *testing.T) {
		// unparseable ARN would drop down to looking up named profile, which will be invalid for this test, so we get 2 for 1
		profile = aws.String("aws:arn::role/Admin")

		if err := resolveConfig(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("bad jump role arn", func(t *testing.T) {
		profile = aws.String("default")
		jumpArn = aws.String("aws:arn::role/Admin")

		if err := resolveConfig(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("user duration", func(t *testing.T) {
		d := 8 * time.Hour
		profile = aws.String("default")
		roleDuration = &d
		jumpArn = aws.String(ev["JUMP_ROLE_ARN"])

		if err := resolveConfig(); err != nil {
			t.Error(err)
			return
		}

		if cfg.DurationSeconds != int(d.Seconds()) || cfg.CredentialsDuration != d {
			t.Error("data mismatch")
		}
	})
}

func TestAwsSession(t *testing.T) {
	t.Run("empty config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Error("did not see expected panic")
			}
		}()
		cfg = new(config.AwsConfig)
		awsSession()
	})

	t.Run("good", func(t *testing.T) {
		profile = aws.String("aProfile")
		verbose = aws.Bool(true)

		cfg = &config.AwsConfig{AwsConfig: new(cfglib.AwsConfig)}
		cfg.Region = "us-east-1"

		awsSession()

		if *ses.Config.Region != cfg.Region || !ses.Config.LogLevel.AtLeast(aws.LogDebug) {
			t.Error("data mismatch")
		}
	})

	t.Run("arn profile", func(t *testing.T) {
		profile = aws.String("arn:aws:iam::1234567890:role/Role")
		cfg = &config.AwsConfig{AwsConfig: new(cfglib.AwsConfig)}
		cfg.Region = "us-east-2"
		cfg.RoleArn = *profile

		awsSession()

		if *ses.Config.Region != cfg.Region {
			t.Error("data mismatch")
		}
	})

	t.Run("source profile", func(t *testing.T) {
		profile = aws.String("aProfile")
		cfg = &config.AwsConfig{AwsConfig: new(cfglib.AwsConfig)}
		cfg.Region = "us-west-1"
		cfg.SourceProfile = "source"

		awsSession()

		if *ses.Config.Region != cfg.Region {
			t.Error("data mismatch")
		}
	})
}

func TestPrintRoles(t *testing.T) {
	usr = &identity.Identity{
		IdentityType: "user",
		Username:     "mock-user",
	}

	// This isn't testable any more now that we're going Fatal() on error
	//t.Run("error", func(t *testing.T) {
	//	idp = &mockIdp{test: "error"}
	//	printRoles()
	//})

	t.Run("empty", func(t *testing.T) {
		idp = &mockIdp{test: "empty"}
		printRoles()
	})

	t.Run("good", func(t *testing.T) {
		idp = new(mockIdp)
		printRoles()
	})
}

func Example_printRoles() {
	usr = &identity.Identity{
		IdentityType: "user",
		Username:     "mock-user",
	}

	idp = new(mockIdp)

	printRoles()
	// Output:
	// Available role ARNs for mock-user
	//   arn:aws:iam::1234567890:role/Admin
}

func Test_printMfa(t *testing.T) {
	usr = &identity.Identity{
		IdentityType: "user",
		Username:     "mock-user",
	}

	// This isn't testable any more now that we're going Fatal() on error
	//t.Run("error", func(t *testing.T) {
	//	m := &mockIam{test: "error"}
	//	printMfa(m)
	//})

	t.Run("empty", func(t *testing.T) {
		m := &mockIam{test: "empty"}
		printMfa(m)
	})

	t.Run("good", func(t *testing.T) {
		m := new(mockIam)
		printMfa(m)
	})
}

func Example_printMfa() {
	usr = &identity.Identity{
		IdentityType: "user",
		Username:     "mock-user",
	}

	printMfa(new(mockIam))
	// Output:
	// 123456
}

func TestSamlClientWithReauth(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "X-MockTest-Only,X-MockTest-NoAuth")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<EntityDescriptor entityID="https://localhost:443/auth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://%s/auth/SSOPOST/metaAlias/realm/saml-idp"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, r.Host)
	}))
	defer s.Close()

	u, _ := url.Parse(s.URL)
	cfg = &config.AwsConfig{AwsConfig: new(cfglib.AwsConfig)}
	cfg.SamlUsername = "good"
	cfg.SamlMetadataUrl = u

	cookieFile = os.DevNull
	samlPass = aws.String("bad")
	mfaCode = aws.String("")

	c, err := samlClientWithReauth()
	if err != nil {
		t.Error(err)
		return
	}

	if c.Client().Username != cfg.SamlUsername || c.Client().Password != *samlPass {
		t.Error("data mismatch")
	}
}

type mockIdp struct {
	identity.Provider
	test string
}

func (p *mockIdp) Roles(user ...string) (identity.Roles, error) {
	if p.test == "error" {
		return nil, fmt.Errorf("I'm an error")
	}

	if p.test == "empty" {
		return []string{}, nil
	}

	return []string{
		"arn:aws:iam::1234567890:role/Admin",
		"arn:aws:iam::*:role/ReadOnly",
		"arn:aws:iam::0987654321:*",
		"*",
	}, nil
}

type mockIam struct {
	iamiface.IAMAPI
	test string
}

func (m *mockIam) ListMFADevices(in *iam.ListMFADevicesInput) (*iam.ListMFADevicesOutput, error) {
	if m.test == "error" {
		return nil, fmt.Errorf("I'm an error")
	}

	if m.test == "empty" {
		return &iam.ListMFADevicesOutput{IsTruncated: aws.Bool(false), MFADevices: []*iam.MFADevice{}}, nil
	}

	return &iam.ListMFADevicesOutput{
		IsTruncated: aws.Bool(false),
		MFADevices:  []*iam.MFADevice{&iam.MFADevice{SerialNumber: aws.String("123456")}},
	}, nil
}
