package credentials

import (
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go/awstesting/mock"
	"github.com/mmmorris1975/aws-runas/shared"
	"testing"
	"time"
)

func TestNewSamlRoleProvider(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		p := newSamlRoleProvider()

		if p.Client == nil {
			t.Error("invalid Client")
		}

		if p.Duration != AssumeRoleDurationDefault {
			t.Error("invalid default duration")
		}

		if p.Logger == nil {
			t.Error("invalid default logger")
		}
	})

	t.Run("nil config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewAssumeRoleProvider with nil config")
			}
		}()
		NewSamlRoleProvider(nil, "", new(SamlAssertion))
	})
}

func TestSamlRoleProvider_Retrieve(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		p := newSamlRoleProvider()
		p.Cache = new(memCredCache)

		v, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.ProviderName != SamlRoleProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("zero duration", func(t *testing.T) {
		p := newSamlRoleProvider()
		p.Duration = 0 * time.Second

		v, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.ProviderName != SamlRoleProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("short duration", func(t *testing.T) {
		p := newSamlRoleProvider()
		p.Duration = 1 * time.Second

		v, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.ProviderName != SamlRoleProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("long duration", func(t *testing.T) {
		p := newSamlRoleProvider()
		p.Duration = 100 * time.Hour

		v, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.ProviderName != SamlRoleProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("invalid role arn", func(t *testing.T) {
		p := newSamlRoleProvider()
		p.RoleArn = ""

		_, err := p.Retrieve()
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("invalid saml assertion", func(t *testing.T) {
		p := newSamlRoleProvider()
		p.samlAssertion = new(SamlAssertion)

		_, err := p.Retrieve()
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("missing principal arn", func(t *testing.T) {
		p := newSamlRoleProvider()
		p.RoleArn = "badRole"

		_, err := p.Retrieve()
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestSamlRoleProvider_Retrieve_Cache(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := &memCredCache{
			creds: &Credentials{
				AccessKeyId:     "AKcached",
				SecretAccessKey: "SKcached",
				Token:           "STcached",
				Expiration:      time.Now().Add(6 * time.Hour),
			},
		}
		p := newSamlRoleProvider()
		p.Cache = c

		v, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if v.AccessKeyID != "AKcached" || v.SecretAccessKey != "SKcached" || v.SessionToken != "STcached" {
			t.Error("credential mismatch")
			return
		}
	})

	t.Run("expired", func(t *testing.T) {
		c := &memCredCache{
			creds: &Credentials{
				AccessKeyId:     "AKcached",
				SecretAccessKey: "SKcached",
				Token:           "STcached",
				Expiration:      time.Now().Add(-6 * time.Hour),
			},
		}
		p := newSamlRoleProvider()
		p.Cache = c

		v, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if v.AccessKeyID == "AKcached" || v.SecretAccessKey == "SKcached" || v.SessionToken == "STcached" {
			t.Error("unexpected credential match")
			return
		}
	})
}

func TestSamlRoleProvider_ClearCache(t *testing.T) {
	p := newSamlRoleProvider()

	t.Run("no cache", func(t *testing.T) {
		p.Cache = nil
		if err := p.ClearCache(); err != nil {
			t.Error(err)
		}
	})

	t.Run("with cache", func(t *testing.T) {
		p.Cache = &memCredCache{
			creds: &Credentials{
				AccessKeyId:     "AKcached",
				SecretAccessKey: "SKcached",
				Token:           "STcached",
				Expiration:      time.Now().Add(-6 * time.Hour),
			},
		}

		if err := p.ClearCache(); err != nil {
			t.Error(err)
			return
		}

		if !p.Cache.Load().Expiration.IsZero() {
			t.Error("cache was not cleared")
		}
	})
}

func newSamlRoleProvider() *samlRoleProvider {
	r := "arn:aws:iam::1234567890:role/mockRole"
	a := fmt.Sprintf(">%s,arn:aws:iam::1234567890:saml-provider/mockPrincipal<", r)
	saml := SamlAssertion(base64.StdEncoding.EncodeToString([]byte(a)))

	p := NewSamlRoleProvider(mock.Session, r, &saml)
	p.Client = new(stsMock)
	p.Logger = new(shared.DefaultLogger)
	return p
}
