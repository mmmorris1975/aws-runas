package credentials

import (
	"github.com/aws/aws-sdk-go/awstesting/mock"
	"github.com/mmmorris1975/aws-runas/shared"
	"testing"
	"time"
)

func TestNewSessionTokenProvider(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		p := NewSessionTokenProvider(mock.Session)

		if p.Client == nil {
			t.Error("invalid Client")
		}

		if p.Duration != SessionTokenDurationDefault {
			t.Error("invalid default duration")
		}

		if p.Logger == nil {
			t.Error("invalid default logger")
		}

		if p.TokenProvider == nil {
			t.Error("invalid default token provider")
		}
	})

	t.Run("nil config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewSessionTokenProvider with nil config")
			}
		}()
		NewSessionTokenProvider(nil)
	})
}

//nolint:gocyclo
func TestSessionTokenProvider_Retrieve(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		v, err := newSessionTokenProvider().Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.ProviderName != SessionTokenProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("zero duration", func(t *testing.T) {
		p := newSessionTokenProvider()
		p.Duration = 0 * time.Second

		v, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.ProviderName != SessionTokenProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("short duration", func(t *testing.T) {
		p := newSessionTokenProvider()
		p.Duration = 1 * time.Second

		v, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.ProviderName != SessionTokenProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("long duration", func(t *testing.T) {
		p := newSessionTokenProvider()
		p.Duration = 100 * time.Hour

		v, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.ProviderName != SessionTokenProviderName {
			t.Error("invalid credentials")
		}
	})
}

func TestSessionTokenProvider_Retrieve_Mfa(t *testing.T) {
	t.Run("good code", func(t *testing.T) {
		p := newSessionTokenProvider()
		p.SerialNumber = "mfa"
		p.TokenCode = "123456"

		v, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.ProviderName != SessionTokenProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("bad code", func(t *testing.T) {
		p := newSessionTokenProvider()
		p.SerialNumber = "mfa"
		p.TokenCode = "abcdef"

		_, err := p.Retrieve()
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("prompt", func(t *testing.T) {
		p := newSessionTokenProvider()
		p.SerialNumber = "mfa"
		p.TokenProvider = func() (string, error) {
			return "123456", nil
		}

		v, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.ProviderName != SessionTokenProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("nil provider", func(t *testing.T) {
		p := newSessionTokenProvider()
		p.SerialNumber = "mfa"
		p.TokenProvider = nil

		_, err := p.Retrieve()
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestSessionTokenProvider_Retrieve_Cache(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := &memCredCache{
			creds: &Credentials{
				AccessKeyId:     "AKcached",
				SecretAccessKey: "SKcached",
				Token:           "STcached",
				Expiration:      time.Now().Add(6 * time.Hour),
			},
		}
		p := newSessionTokenProvider()
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
		p := newSessionTokenProvider()
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

func newSessionTokenProvider() *SessionTokenProvider {
	p := NewSessionTokenProvider(mock.Session)
	p.Client = new(stsMock)
	p.Logger = new(shared.DefaultLogger)
	return p
}
