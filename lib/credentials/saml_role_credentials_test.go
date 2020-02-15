package credentials

import (
	"aws-runas/lib/cache"
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/awstesting/mock"
	"testing"
	"time"
)

func TestNewSamlRoleCredentials(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		r := "arn:aws:iam::1234567890:role/aRole"
		p := "arn:aws:iam::1234567890:saml-provider/aPrincipal"
		c := NewSamlRoleCredentials(mock.Session, r, fmt.Sprintf(">%s,%s<", r, p))

		if !c.IsExpired() {
			t.Errorf("expected expired credentials")
		}
	})

	t.Run("nil config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewSamlRoleCredentials with nil config")
			}
		}()
		NewSamlRoleCredentials(nil, "aRole", "")
	})

	t.Run("with options", func(t *testing.T) {
		c := NewSamlRoleCredentials(mock.Session, "aRole", "", func(p *SamlRoleProvider) {
			p.Duration = AssumeRoleMaxDuration
			p.SerialNumber = "abcd"
		})

		if !c.IsExpired() {
			t.Errorf("expected expired credentials")
		}
	})
}

func TestSamlRoleProvider_RetrieveNoCache(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		p := newSamlRoleProvider()

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != SamlRoleProviderName {
			t.Error("provider name mismatch")
		}

		if !c.HasKeys() {
			t.Error("bad keys")
		}
	})

	t.Run("long duration", func(t *testing.T) {
		p := newSamlRoleProvider()
		p.Duration = 100 * time.Hour

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != SamlRoleProviderName {
			t.Error("provider name mismatch")
		}

		if !c.HasKeys() {
			t.Error("bad keys")
		}
	})

	t.Run("invalid principal", func(t *testing.T) {
		p := newSamlRoleProvider()
		p.principalArn = "arn:aws:iam::1234567890:role/PowerUser"

		_, err := p.Retrieve()
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("invalid SAMLAssertion", func(t *testing.T) {
		p := newSamlRoleProvider()
		p.SAMLAssertion = fmt.Sprintf("%s,%s", "arn:aws:iam::1234567890:role/ReadOnly", p.principalArn)

		_, err := p.Retrieve()
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestSamlRoleProvider_RetrieveCache(t *testing.T) {
	t.Run("empty cache", func(t *testing.T) {
		cc := new(credentialCacheMock)
		p := newSamlRoleProvider()
		p.Cache = cc

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != SamlRoleProviderName {
			t.Error("provider name mismatch")
		}

		if !c.HasKeys() {
			t.Error("bad keys")
		}

		if c.AccessKeyID != *cc.AccessKeyId || c.SecretAccessKey != *cc.SecretAccessKey || c.SessionToken != *cc.SessionToken {
			t.Error("data mismatch")
		}
	})

	t.Run("expired cache", func(t *testing.T) {
		exp := cache.CacheableCredentials{
			AccessKeyId:     aws.String("AKIAexpired"),
			SecretAccessKey: aws.String("expired"),
			SessionToken:    aws.String("expired"),
			Expiration:      aws.Time(time.Now().Add(-1 * time.Hour)),
		}

		cc := new(credentialCacheMock)
		cc.CacheableCredentials = &exp

		p := newSamlRoleProvider()
		p.Cache = cc

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != SamlRoleProviderName {
			t.Error("provider name mismatch")
		}

		if !c.HasKeys() {
			t.Error("bad keys")
		}

		if c.AccessKeyID != *cc.AccessKeyId || c.SecretAccessKey != *cc.SecretAccessKey || c.SessionToken != *cc.SessionToken {
			t.Error("data mismatch")
		}
	})

	t.Run("valid cache", func(t *testing.T) {
		exp := cache.CacheableCredentials{
			AccessKeyId:     aws.String("AKIAvalid"),
			SecretAccessKey: aws.String("valid"),
			SessionToken:    aws.String("valid"),
			Expiration:      aws.Time(time.Now().Add(1 * time.Hour)),
		}

		cc := new(credentialCacheMock)
		cc.CacheableCredentials = &exp

		p := newSamlRoleProvider()
		p.Cache = cc

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != SamlRoleProviderName {
			t.Error("provider name mismatch")
		}

		if !c.HasKeys() {
			t.Error("bad keys")
		}

		if c.AccessKeyID != *cc.AccessKeyId || c.SecretAccessKey != *cc.SecretAccessKey || c.SessionToken != *cc.SessionToken {
			t.Error("data mismatch")
		}
	})
}

func newSamlRoleProvider() *SamlRoleProvider {
	princArn := "arn:aws:iam::1234567890:saml-provider/mySAML"

	p := new(SamlRoleProvider)
	p.AssumeRoleProvider = &AssumeRoleProvider{
		stsCredentialProvider: newStsCredentialProvider(mock.Session),
		RoleARN:               "arn:aws:iam::1234567890:role/Admin",
	}
	p.client = new(stsMock)
	data := fmt.Sprintf(">%s,%s<", p.RoleARN, princArn)
	p.SAMLAssertion = base64.StdEncoding.EncodeToString([]byte(data))
	p.setPrincipalArn()

	return p
}
