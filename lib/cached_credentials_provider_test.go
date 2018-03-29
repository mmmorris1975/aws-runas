package lib

import (
	"fmt"
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

func (m *mockSessionTokenProvider) AssumeRole() (credentials.Value, error) {
	v := credentials.Value{
		AccessKeyID:     "MockAssumeRoleAccessKey",
		SecretAccessKey: "MockAssumeRoleSecretKey",
		SessionToken:    "MockAssumeRoleSessionToken",
		ProviderName:    "MockCredentialsProvider",
	}
	return v, nil
}

func newSessionTokenProvider() *mockSessionTokenProvider {
	opts := SessionTokenProviderOptions{
		LogLevel: logo.INFO,
	}

	m := new(mockSessionTokenProvider)
	m.setAttrs(new(AWSProfile), &opts)
	return m
}

func TestCacheFileDefault(t *testing.T) {
	os.Unsetenv("AWS_CONFIG_FILE")
	m := newSessionTokenProvider()
	if !strings.HasSuffix(m.CacheFile(), filepath.Join(string(filepath.Separator), ".aws_session_token_")) {
		t.Errorf("Cache file path does not have expected contents: %s", m.CacheFile())
	}
}

func ExampleCacheFileEnv() {
	os.Setenv("AWS_CONFIG_FILE", "aws.cfg")
	m := newSessionTokenProvider()
	fmt.Println(m.CacheFile())
	// Output:
	// .aws_session_token_
}

func TestExpirationTimeEpoch(t *testing.T) {
	m := newSessionTokenProvider()
	e := m.ExpirationTime()
	if !e.Equal(time.Unix(0, 0)) {
		t.Errorf("Expiration time for unset credentials != Unix epoch time")
	}
}

func TestIsExpiredNoCreds(t *testing.T) {
	m := newSessionTokenProvider()
	if !m.IsExpired() {
		t.Errorf("Expected IsExpired() for no credentials to be true, got %v", m.IsExpired())
	}
}

func ExampleSessionTokenRetrieve() {
	m := newSessionTokenProvider()
	c, err := m.Retrieve()
	if err != nil {
		fmt.Printf("Unexpected error during Retrieve(): %v", err)
	}
	fmt.Println(c.AccessKeyID)
	fmt.Println(c.SecretAccessKey)
	fmt.Println(c.SessionToken)
	fmt.Println(c.ProviderName)
	// Output:
	// MockSessionTokenAccessKey
	// MockSessionTokenSecretKey
	// MockSessionToken
	// MockCredentialsProvider
}

func TestSessionTokenExpired(t *testing.T) {

}

func ExampleAssumeRole() {
	m := newSessionTokenProvider()
	c, err := m.AssumeRole()
	if err != nil {
		fmt.Printf("Unexpected error during AssumeRole(): %v", err)
	}
	fmt.Println(c.AccessKeyID)
	fmt.Println(c.SecretAccessKey)
	fmt.Println(c.SessionToken)
	fmt.Println(c.ProviderName)
	// Output:
	// MockAssumeRoleAccessKey
	// MockAssumeRoleSecretKey
	// MockAssumeRoleSessionToken
	// MockCredentialsProvider
}
