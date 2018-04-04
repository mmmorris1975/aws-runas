package lib

import (
	"github.com/mbndr/logo"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewSessionTokenProvider(t *testing.T) {
	t.Run("ProfileNil", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewSessionTokenProvider with nil profile")
			}
		}()
		NewSessionTokenProvider(nil, new(CachedCredentialsProviderOptions))
	})

	t.Run("OptionsNil", func(t *testing.T) {
		p := NewSessionTokenProvider(new(AWSProfile), nil)
		if !strings.HasSuffix(p.(*sessionTokenProvider).cacher.CacheFile(), "_") {
			t.Errorf("Unexpected value returned calling NewSessionTokenProvider with nil options")
		}
	})
}

func TestSessionTokenProvider_IsExpired(t *testing.T) {
	opts := &CachedCredentialsProviderOptions{LogLevel: logo.DEBUG}
	t.Run("CredsNil", func(t *testing.T) {
		p := NewSessionTokenProvider(new(AWSProfile), opts)
		if !p.IsExpired() {
			t.Errorf("Expected IsExpired() to be true for nil creds")
		}
	})

	t.Run("True", func(t *testing.T) {
		p := NewSessionTokenProvider(new(AWSProfile), opts)
		p.(*sessionTokenProvider).creds = &CachableCredentials{Expiration: 500}
		p.(*sessionTokenProvider).cacher = &credentialsCacher{file: os.DevNull}
		if !p.IsExpired() {
			t.Errorf("Expected IsExpired() to be true for expired creds")
		}
	})

	t.Run("False", func(t *testing.T) {
		p := NewSessionTokenProvider(new(AWSProfile), opts)
		p.(*sessionTokenProvider).creds = &CachableCredentials{Expiration: time.Now().Unix() + 500}
		p.(*sessionTokenProvider).cacher = &credentialsCacher{file: os.DevNull}
		if p.IsExpired() {
			t.Errorf("Expected IsExpired() to be false for non-expired creds")
		}
	})
}
