package credentials

import (
	"aws-runas/lib/cache"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/awstesting/mock"
	"testing"
	"time"
)

func TestNewAssumeRoleCredentials(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := NewAssumeRoleCredentials(mock.Session, "aRole")

		if !c.IsExpired() {
			t.Errorf("expected expired credentials")
		}
	})

	t.Run("nil config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewAssumeRoleCredentials with nil config")
			}
		}()
		NewAssumeRoleCredentials(nil, "aRole")
	})

	t.Run("with options", func(t *testing.T) {
		c := NewAssumeRoleCredentials(mock.Session, "aRole", func(p *AssumeRoleProvider) {
			p.Duration = AssumeRoleMaxDuration
			p.SerialNumber = "abcd"
		})

		if !c.IsExpired() {
			t.Errorf("expected expired credentials")
		}
	})
}

func TestAssumeRoleProvider_RetrieveNoCache(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.ExternalID = "ItsAllGood"

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != AssumeRoleProviderName {
			t.Error("provider name mismatch")
		}

		if !c.HasKeys() {
			t.Error("bad keys")
		}
	})

	t.Run("long duration", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.Duration = 100 * time.Hour

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != AssumeRoleProviderName {
			t.Error("provider name mismatch")
		}

		if !c.HasKeys() {
			t.Error("bad keys")
		}
	})

	t.Run("bad ExternalID", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.ExternalID = "ItsNotGood"

		_, err := p.Retrieve()
		if err == nil {
			t.Errorf("did not receive expected error")
		}
	})
}

func TestAssumeRoleProvider_RetrieveCache(t *testing.T) {
	t.Run("empty cache", func(t *testing.T) {
		cc := new(credentialCacheMock)
		p := newAssumeRoleProvider()
		p.Cache = cc

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != AssumeRoleProviderName {
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

		p := newAssumeRoleProvider()
		p.Cache = cc

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != AssumeRoleProviderName {
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

		p := newAssumeRoleProvider()
		p.Cache = cc

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != AssumeRoleProviderName {
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

func TestAssumeRoleProvider_RetrieveMfa(t *testing.T) {
	t.Run("no token", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.TokenProvider = nil
		p.SerialNumber = "MFAtime"

		_, err := p.Retrieve()
		if err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("bad token", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.SerialNumber = "MFAtime"
		p.TokenCode = "abcdef"

		_, err := p.Retrieve()
		if err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("token func", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.SerialNumber = "MFAtime"
		p.TokenProvider = func() (s string, e error) {
			return "123456", nil
		}

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != AssumeRoleProviderName {
			t.Error("provider name mismatch")
		}

		if !c.HasKeys() {
			t.Error("bad keys")
		}
	})

	t.Run("token func error", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.SerialNumber = "MFAtime"
		p.TokenProvider = func() (s string, e error) {
			return "", fmt.Errorf("mfa error")
		}

		_, err := p.Retrieve()
		if err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func newAssumeRoleProvider() *AssumeRoleProvider {
	p := &AssumeRoleProvider{
		stsCredentialProvider: newStsCredentialProvider(mock.Session),
		RoleARN:               "arn:aws:iam::1234567890:role/Admin",
	}
	p.client = new(stsMock)
	return p
}
