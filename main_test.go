package main

import (
	"aws-runas/lib/config"
	"aws-runas/lib/identity"
	"aws-runas/lib/saml"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/awstesting/mock"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	cfglib "github.com/mmmorris1975/aws-config/config"
	"github.com/mmmorris1975/simple-logger/logger"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

var emptyConfig = &config.AwsConfig{AwsConfig: new(cfglib.AwsConfig)}

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

		cfg = emptyConfig
		cfg.Region = "us-east-1"

		awsSession()

		if *ses.Config.Region != cfg.Region || !ses.Config.LogLevel.AtLeast(aws.LogDebug) {
			t.Error("data mismatch")
		}
	})

	t.Run("arn profile", func(t *testing.T) {
		profile = aws.String("arn:aws:iam::1234567890:role/Role")
		cfg = emptyConfig
		cfg.Region = "us-east-2"
		cfg.RoleArn = *profile

		awsSession()

		if *ses.Config.Region != cfg.Region {
			t.Error("data mismatch")
		}
	})

	t.Run("source profile", func(t *testing.T) {
		profile = aws.String("aProfile")
		cfg = emptyConfig
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
	samlClient = nil
	usr = &identity.Identity{
		IdentityType: "user",
		Username:     "mock-user",
	}

	printMfa(new(mockIam))
	// Output:
	// 123456
}

func TestSamlClientWithReauth(t *testing.T) {
	u, _ := url.Parse(samlSvr.URL)
	cfg = emptyConfig
	cfg.SamlUsername = "good"
	cfg.SamlAuthUrl = u

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

func TestCheckRefresh(t *testing.T) {
	cfg = emptyConfig
	cfg.Profile = "mock"
	cfg.SourceProfile = ""
	profile = aws.String(cfg.Profile)

	t.Run("no refresh", func(t *testing.T) {
		refresh = aws.Bool(false)
		checkRefresh()
	})

	t.Run("iam user", func(t *testing.T) {
		refresh = aws.Bool(true)
		usr = &identity.Identity{IdentityType: "user", Provider: identity.IdentityProviderAws}
		checkRefresh()
	})

	t.Run("saml user", func(t *testing.T) {
		refresh = aws.Bool(true)
		usr = &identity.Identity{IdentityType: "user", Provider: saml.IdentityProviderSaml}
		checkRefresh()
	})
}

func TestPrintCredExpire(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		c := credentials.NewCredentials(&mockCredProvider{})
		printCredExpire(c)
	})

	t.Run("expired", func(t *testing.T) {
		c := credentials.NewCredentials(&mockCredProvider{expired: true})
		printCredExpire(c)
	})
}

func TestHandleAwsUserCredentials(t *testing.T) {
	ses = mock.Session
	usr = new(identity.Identity)
	mfaCode = aws.String("")
	profile = aws.String("mock")

	t.Run("long role", func(t *testing.T) {
		cfg = emptyConfig
		cfg.RoleArn = "arn:aws:iam::1234567890:role/Admin"
		cfg.CredentialsDuration = 4 * time.Hour
		handleAwsUserCredentials()
	})

	t.Run("session creds", func(t *testing.T) {
		cfg = emptyConfig
		sesCreds = aws.Bool(true)
		cfg.RoleArn = ""
		handleAwsUserCredentials()
	})

	t.Run("standard role", func(t *testing.T) {
		cfg = emptyConfig
		cfg.RoleArn = "arn:aws:iam::1234567890:role/Admin"
		cfg.CredentialsDuration = 1 * time.Minute
		sesCreds = aws.Bool(false)
		handleAwsUserCredentials()
	})
}

func TestUpdateEnv(t *testing.T) {
	profile = aws.String("mock")
	creds := credentials.Value{
		AccessKeyID:     "mockAK",
		SecretAccessKey: "mockSK",
	}

	defer func() {
		v := []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
			"AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWSRUNAS_PROFILE"}
		for _, x := range v {
			os.Unsetenv(x)
		}
	}()

	t.Run("basic", func(t *testing.T) {
		cfg = emptyConfig
		updateEnv(creds)

		if _, ok := os.LookupEnv("AWS_SESSION_TOKEN"); ok {
			t.Error("AWS_SESSION_TOKEN unexpectedly set")
		}

		if ak := os.Getenv("AWS_ACCESS_KEY_ID"); ak != creds.AccessKeyID {
			t.Error("access key mismatch")
		}

		if sk := os.Getenv("AWS_SECRET_ACCESS_KEY"); sk != creds.SecretAccessKey {
			t.Error("secret key mismatch")
		}
	})

	t.Run("with region", func(t *testing.T) {
		cfg = emptyConfig
		cfg.Region = "us-east-2"

		updateEnv(creds)

		if r := os.Getenv("AWS_REGION"); r != cfg.Region {
			t.Error("region mismatch")
		}
	})

	t.Run("session creds", func(t *testing.T) {
		cfg = emptyConfig
		creds.SessionToken = "sessionTok"

		updateEnv(creds)

		if r := os.Getenv("AWS_SESSION_TOKEN"); r != creds.SessionToken {
			t.Error("session token mismatch")
		}
	})
}

func TestWrapCmd(t *testing.T) {
	t.Run("unwrapped", func(t *testing.T) {
		cmd := wrapCmd([]string{"true"})

		if len(cmd) > 1 || cmd[0] != "true" {
			t.Error("data mismatch")
		}
	})

	t.Run("wrapped", func(t *testing.T) {
		os.Setenv("SHELL", "/mock/bash")
		defer os.Unsetenv("SHELL")

		cmd := wrapCmd([]string{"not-a-thing", "-v"})

		if len(cmd) != 4 || cmd[0] != "/mock/bash" {
			t.Log(cmd)
			t.Error("data mismatch")
		}
	})

	t.Run("empty", func(t *testing.T) {
		cmd := wrapCmd([]string{})
		if len(cmd) > 0 {
			t.Error("data mismatch")
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
}

func TestAwsUser(t *testing.T) {
	ses = mock.Session

	// This may be tricky, since we can't easily inject an STS mock into our IdentityProvider
	//t.Run("aws user", func(t *testing.T) {
	//	cfg = emptyConfig
	//})

	t.Run("saml user", func(t *testing.T) {
		u, _ := url.Parse(samlSvr.URL)
		samlPass = aws.String("")
		mfaCode = aws.String("")

		cfg = emptyConfig
		cfg.SamlAuthUrl = u

		err := awsUser()
		if err != nil {
			t.Error(err)
			return
		}

		if usr.Username != "mock-user" || usr.Provider != "MockSamlProvider" {
			t.Error("data mismatch")
		}
	})
}

func TestRoleCredCacheName(t *testing.T) {
	cfg = emptyConfig
	cfg.RoleArn = "arn:aws:iam::1234567890:role/managed-role/AcctAdmin"

	t.Run("named profile", func(t *testing.T) {
		profile = aws.String("mock")
		f := roleCredCacheName()

		if !strings.HasSuffix(f, ".aws_assume_role_mock") {
			t.Error("data mismatch")
		}
	})

	t.Run("arn profile", func(t *testing.T) {
		profile = aws.String("arn:aws:iam::1234567890:role/managed-role/AcctAdmin")
		f := roleCredCacheName()

		if !strings.HasSuffix(f, ".aws_assume_role_1234567890-AcctAdmin") {
			t.Error("data mismatch")
		}
	})
}

func TestSessionCredCacheName(t *testing.T) {
	cfg = emptyConfig

	t.Run("source profile", func(t *testing.T) {
		cfg.SourceProfile = "my-source"
		f := sessionCredCacheName()

		if !strings.HasSuffix(f, ".aws_session_token_my-source") {
			t.Error("data mismatch")
		}
	})

	t.Run("named profile", func(t *testing.T) {
		cfg.SourceProfile = ""
		profile = aws.String("my-profile")
		f := sessionCredCacheName()

		if !strings.HasSuffix(f, ".aws_session_token_my-profile") {
			t.Error("data mismatch")
		}
	})

	t.Run("default", func(t *testing.T) {
		cfg.SourceProfile = ""
		profile = aws.String("")

		f := sessionCredCacheName()

		if !strings.HasSuffix(f, ".aws_session_token_default") {
			t.Error("data mismatch")
		}
	})
}

func TestHandleSamlUserCredentials(t *testing.T) {
	t.Run("nil client", func(t *testing.T) {
		samlClient = nil
		if _, err := handleSamlUserCredentials(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("error", func(t *testing.T) {
		samlClient = &mockSamlClient{error: true}
		if _, err := handleSamlUserCredentials(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("good", func(t *testing.T) {
		samlClient = new(mockSamlClient)
		ses = mock.Session
		log = logger.StdLogger
		profile = aws.String("mock")
		usr = &identity.Identity{
			IdentityType: "user",
			Provider:     saml.IdentityProviderSaml,
			Username:     "mock-user",
		}

		cfg = emptyConfig
		cfg.RoleArn = "arn:aws:iam::1234567890:role/Admin"
		cfg.JumpRoleArn, _ = arn.Parse("arn:aws:iam::0987654321:role/Jump")
		cfg.MfaSerial = "999999"

		if _, err := handleSamlUserCredentials(); err != nil {
			t.Error(err)
		}
	})
}

func TestRunEcsSvc(t *testing.T) {
	runEcsSvc(credentials.NewCredentials(new(mockCredProvider)))
}

type mockIdp struct {
	identity.Provider
	test string
}

func (p *mockIdp) Roles(user ...string) (identity.Roles, error) {
	if p.test == "error" {
		return nil, fmt.Errorf("this is an error")
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
		return nil, fmt.Errorf("this is an error")
	}

	if m.test == "empty" {
		return &iam.ListMFADevicesOutput{IsTruncated: aws.Bool(false), MFADevices: []*iam.MFADevice{}}, nil
	}

	return &iam.ListMFADevicesOutput{
		IsTruncated: aws.Bool(false),
		MFADevices:  []*iam.MFADevice{&iam.MFADevice{SerialNumber: aws.String("123456")}},
	}, nil
}

type mockCredProvider struct {
	*credentials.Expiry
	expired bool
}

func (p *mockCredProvider) IsExpired() bool {
	return p.Expiry.IsExpired()
}

func (p *mockCredProvider) Retrieve() (credentials.Value, error) {
	if p.Expiry == nil {
		p.Expiry = new(credentials.Expiry)
	}

	d := 1 * time.Hour
	if p.expired {
		d = d * -1
	}
	p.Expiry.SetExpiration(time.Now().Add(d), 1*time.Second)
	return credentials.Value{}, nil
}

// An STS client we can use for testing to avoid calls out to AWS
type mockStsClient struct {
	stsiface.STSAPI
}

func (c *mockStsClient) GetCallerIdentity(in *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	return new(sts.GetCallerIdentityOutput).
		SetAccount("123456789012").
		SetArn("arn:aws:iam::123456789012:user/bob").
		SetUserId("AIDAB0B"), nil
}

var samlSvr = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Headers", "X-MockTest-Only,X-MockTest-NoAuth")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<EntityDescriptor entityID="https://localhost:443/auth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://%s/auth/SSOPOST/metaAlias/realm/saml-idp"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, r.Host)
}))

type mockSamlClient struct {
	saml.AwsClient
	error bool
}

func (c *mockSamlClient) AwsSaml() (string, error) {
	if c.error {
		return "", fmt.Errorf("this is an error")
	}
	return "><", nil
}

func (c *mockSamlClient) GetSessionDuration() (int64, error) {
	if c.error {
		return -1, fmt.Errorf("this is an error")
	}
	return 12345, nil
}
