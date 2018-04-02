package lib

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/mbndr/logo"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type mockSessionTokenProvider struct {
	awsAssumeRoleProvider
}

// override Retrieve() and AssumeRole() so we can bypass/mock calls to AWS services
func (m *mockSessionTokenProvider) Retrieve() (credentials.Value, error) {
	// lazy load credentials
	c, err := m.credsFromFile()
	if err == nil {
		m.log.Debugf("Found cached session token credentials")
		m.creds = c
	}

	if m.IsExpired() {
		m.log.Debugf("Detected expired or unset session token credentials, refreshing")
		c = &CachableCredentials{
			Expiration: time.Now().Add(m.sessionTokenDuration).Unix(),
			Value: credentials.Value{
				AccessKeyID:     "MockSessionTokenAccessKey",
				SecretAccessKey: "MockSessionTokenSecretKey",
				SessionToken:    "MockSessionToken",
				ProviderName:    "MockCredentialsProvider",
			},
		}
		m.creds = c
		m.Store()
	}

	return m.creds.Value, nil
}

func (m *mockSessionTokenProvider) AssumeRole(d *time.Duration) (credentials.Value, error) {
	v := credentials.Value{
		AccessKeyID:     "MockAssumeRoleAccessKey",
		SecretAccessKey: "MockAssumeRoleSecretKey",
		SessionToken:    "MockAssumeRoleSessionToken",
		ProviderName:    "MockCredentialsProvider",
	}
	return v, nil
}

func TestProviderDefaults(t *testing.T) {
	os.Unsetenv("AWS_CONFIG_FILE")
	m := new(mockSessionTokenProvider)
	m.setAttrs(new(AWSProfile), &SessionTokenProviderOptions{LogLevel: logo.INFO})

	t.Run("CacheFile", func(t *testing.T) {
		if !strings.HasSuffix(m.CacheFile(), filepath.Join(string(filepath.Separator), ".aws_session_token_")) {
			t.Errorf("Cache file path does not have expected contents: %s", m.CacheFile())
		}
	})
	t.Run("ExpirationEpoch", func(t *testing.T) {
		m.cacheFile = ""
		if !m.ExpirationTime().Equal(time.Unix(0, 0)) {
			t.Errorf("Expiration time for unset credentials != Unix epoch time: %v", m.ExpirationTime())
		}
	})
	t.Run("NoCreds", func(t *testing.T) {
		if !m.IsExpired() {
			t.Errorf("Expected IsExpired() for unset credentials to be true, got %v", m.IsExpired())
		}
	})
	t.Run("AssumeRole", func(t *testing.T) {
		d := ASSUME_ROLE_MAX_DURATION
		c, err := m.AssumeRole(&d)
		if err != nil {
			t.Errorf("Unexpected error during AssumeRole(): %v", err)
		}
		if c.AccessKeyID != "MockAssumeRoleAccessKey" || c.SecretAccessKey != "MockAssumeRoleSecretKey" ||
			c.SessionToken != "MockAssumeRoleSessionToken" || c.ProviderName != "MockCredentialsProvider" {
			t.Errorf("Data mismatch when validating assume role credentials: %v", c)
		}
	})
}

func TestProviderCustomConfig(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", "aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")
	p := AWSProfile{
		Region: "us-west-1",
	}

	opts := SessionTokenProviderOptions{
		LogLevel:             logo.INFO,
		SessionTokenDuration: 8 * time.Hour,
		MfaSerial:            "mock-mfa",
	}
	m := new(mockSessionTokenProvider)
	m.setAttrs(&p, &opts)
	defer os.Remove(m.CacheFile())

	t.Run("CacheFile", func(t *testing.T) {
		if m.CacheFile() != ".aws_session_token_" {
			t.Errorf("Cache file path does not have expected contents: %s", m.CacheFile())
		}
	})
	t.Run("SessionTokenRetrieve", func(t *testing.T) {
		c, err := m.Retrieve()
		if err != nil {
			t.Errorf("Error in Retrieve(): %v", err)
		}
		if c.AccessKeyID != "MockSessionTokenAccessKey" || c.SecretAccessKey != "MockSessionTokenSecretKey" ||
			c.SessionToken != "MockSessionToken" || c.ProviderName != "MockCredentialsProvider" {
			t.Errorf("Data mismatch when validating assume role credentials: %v", c)
		}
	})

	// These tests require that something has called Retrieve()
	t.Run("SessionTokenExpirationTime", func(t *testing.T) {
		if m.ExpirationTime() == time.Unix(0, 0) {
			t.Errorf("Credentials have invalid expiration")
		}
	})
	t.Run("SessionTokenNotExpired", func(t *testing.T) {
		if m.IsExpired() {
			t.Errorf("Unexpected expired credentials")
		}
	})
	t.Run("CredsFromFile", func(t *testing.T) {
		c, err := m.credsFromFile()
		if err != nil {
			t.Errorf("Error loading cached credentials: %v", err)
		}
		if c == nil {
			t.Errorf("nil credentials read from file")
		}
	})
	t.Run("ExpiredCredentials", func(t *testing.T) {
		m.cacheFile = ""
		m.creds.Expiration = time.Now().Add(-5 * time.Second).Unix()
		if m.ExpirationTime().After(time.Now()) {
			t.Errorf("Unexpected future credential expiration time: %v", m.ExpirationTime())
		}
		if !m.IsExpired() {
			t.Errorf("Expected expired credentials, but received valid")
		}
	})
}

func TestNewProviderParams(t *testing.T) {
	os.Unsetenv("AWS_CONFIG_FILE")
	m := new(mockSessionTokenProvider)

	t.Run("NilProfile", func(t *testing.T) {
		defer func() {
			if x := recover(); x != nil {
				t.Logf("Got expected panic() from nil profile")
			} else {
				t.Errorf("Did not see expected panic() from nil profile")
			}
		}()
		m.setAttrs(nil, new(SessionTokenProviderOptions))
	})
	t.Run("NilOptions", func(t *testing.T) {
		defer func() {
			if x := recover(); x != nil {
				t.Logf("Got expected panic() from nil options")
			} else {
				t.Errorf("Did not see expected panic() from nil options")
			}
		}()
		m.setAttrs(new(AWSProfile), nil)
	})
	t.Run("DefaultSessionDuration", func(t *testing.T) {
		if m.sessionTokenDuration != SESSION_TOKEN_DEFAULT_DURATION {
			t.Errorf("Session token duration is not default value")
		}
	})
	t.Run("BelowMinSessionDuration", func(t *testing.T) {
		m.setAttrs(new(AWSProfile), &SessionTokenProviderOptions{SessionTokenDuration: 1 * time.Minute})
		if m.sessionTokenDuration != SESSION_TOKEN_MIN_DURATION {
			t.Errorf("Session token duration is not min value")
		}
	})
	t.Run("AboveMaxSessionDuration", func(t *testing.T) {
		m.setAttrs(new(AWSProfile), &SessionTokenProviderOptions{SessionTokenDuration: 100 * time.Hour})
		if m.sessionTokenDuration != SESSION_TOKEN_MAX_DURATION {
			t.Errorf("Session token duration is not max value")
		}
	})
}

func TestNewSessionTokenProviderDefault(t *testing.T) {
	_, err := NewSessionTokenProvider(new(AWSProfile), new(SessionTokenProviderOptions))
	if err != nil {
		t.Errorf("Unexpected error calling NewSessionTokenProvider(): %v", err)
	}
}

func TestValidateRoleSessionName(t *testing.T) {
	p := awsAssumeRoleProvider{}
	t.Run("NameValid", func(t *testing.T) {
		v := "test"
		n := p.validateRoleSessionName(aws.String(v))
		if *n != v {
			t.Errorf("Expected RoleSessionName == test value, but got: %v", n)
		}
	})
	t.Run("NameNil", func(t *testing.T) {
		n := p.validateRoleSessionName(nil)
		if !strings.HasPrefix(*n, "AWS-RUNAS-") {
			t.Errorf("Expected generated RoleSessionName, but got: %v", n)
		}
	})
}

func TestValidateArn(t *testing.T) {
	p := awsAssumeRoleProvider{}
	t.Run("ArnValid", func(t *testing.T) {
		arn := "arn:aws:iam::666:/role/mock"
		if err := p.validateArn(aws.String(arn)); err != nil {
			t.Errorf("Unexpected error validating valid arn: %v", err)
		}
	})
	t.Run("ArnInvalid", func(t *testing.T) {
		arn := "aws:iam::666:/role/mock"
		if err := p.validateArn(aws.String(arn)); err == nil {
			t.Errorf("Invalid arn was successfully validated, expecting error")
		}
	})
	t.Run("ArnNotIam", func(t *testing.T) {
		arn := "arn:aws:s3:::bucket"
		if err := p.validateArn(aws.String(arn)); err == nil {
			t.Errorf("non-IAM arn was successfully validated, expecting error")
		}
	})
	t.Run("ArnNil", func(t *testing.T) {
		if err := p.validateArn(nil); err == nil {
			t.Errorf("nil arn was successfully validated, expecting error")
		}
	})
}

func TestValidateRoleDuration(t *testing.T) {
	p := awsAssumeRoleProvider{}
	t.Run("DurationValid", func(t *testing.T) {
		d := int64(10800)
		v := p.validateRoleDuration(aws.Int64(d))
		if *v != d {
			t.Errorf("Validation modified expected valid value, wanted: %d, got: %d", d, *v)
		}
	})
	t.Run("DurationMin", func(t *testing.T) {
		v := p.validateRoleDuration(aws.Int64(10))
		if *v != int64(ASSUME_ROLE_MIN_DURATION.Seconds()) {
			t.Errorf("Validation did not return expected min value, got %d", *v)
		}
	})
	t.Run("DurationMax", func(t *testing.T) {
		v := p.validateRoleDuration(aws.Int64(1e6))
		if *v != int64(ASSUME_ROLE_MAX_DURATION.Seconds()) {
			t.Errorf("Validation did not return expected max value, got %d", *v)
		}
	})
	t.Run("DurationNil", func(t *testing.T) {
		v := p.validateRoleDuration(nil)
		if *v != int64(ASSUME_ROLE_DEFAULT_DURATION.Seconds()) {
			t.Errorf("Expected nil role duration to get set to default, got %d", *v)
		}
	})
}
