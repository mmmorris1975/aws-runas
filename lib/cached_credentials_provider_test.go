package lib

import (
	"github.com/mbndr/logo"
	"strings"
	"testing"
	"time"
)

func TestNewCachedCredentialsProvider(t *testing.T) {
	opts := &CachedCredentialsProviderOptions{LogLevel: logo.DEBUG}
	t.Run("ProfileNil", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewCachedCredentialsProvider with nil profile")
			}
		}()
		NewCachedCredentialsProvider(nil, opts)
	})

	t.Run("OptionsNil", func(t *testing.T) {
		p := NewCachedCredentialsProvider(new(AWSProfile), nil)
		if !strings.HasSuffix(p.cacher.CacheFile(), "_") {
			t.Errorf("Unexpected value returned calling NewCachedCredentialsProvider with nil options: %s", p.cacher.CacheFile())
		}
	})
}

func TestCachedCredentialsProvider_CacheFile(t *testing.T) {
	opts := &CachedCredentialsProviderOptions{LogLevel: logo.DEBUG}
	t.Run("SourceProfileSet", func(t *testing.T) {
		prof := &AWSProfile{Name: "mock", SourceProfile: "source"}
		p := NewCachedCredentialsProvider(prof, opts)
		if !strings.HasSuffix(p.CacheFile(), ".aws_cached_credentials_source") {
			t.Errorf("Unexpected value for cache file name with profile name set: %s", p.CacheFile())
		}
	})

	t.Run("SourceProfileUnset", func(t *testing.T) {
		prof := &AWSProfile{Name: "mock", SourceProfile: ""}
		p := NewCachedCredentialsProvider(prof, opts)
		if !strings.HasSuffix(p.CacheFile(), ".aws_cached_credentials_mock") {
			t.Errorf("Unexpected value for cache file name with profile name set: %s", p.CacheFile())
		}
	})
}

func TestCachedCredentialsProvider_IsExpired(t *testing.T) {
	opts := &CachedCredentialsProviderOptions{LogLevel: logo.DEBUG}
	t.Run("CredsNil", func(t *testing.T) {
		p := NewCachedCredentialsProvider(new(AWSProfile), opts)
		if !p.IsExpired() {
			t.Errorf("Expected IsExpired() to be true for nil creds")
		}
	})

	t.Run("True", func(t *testing.T) {
		p := NewCachedCredentialsProvider(new(AWSProfile), opts)
		p.cacher = &credentialsCacher{file: "config/test/cached_creds_expired.json"}
		if !p.IsExpired() {
			t.Errorf("Expected IsExpired() to be true for expired creds")
		}
	})

	t.Run("False", func(t *testing.T) {
		p := NewCachedCredentialsProvider(new(AWSProfile), opts)
		p.cacher = &credentialsCacher{file: "config/test/cached_creds_valid.json"}
		if p.IsExpired() {
			t.Errorf("Expected IsExpired() to be false for non-expired creds")
		}
	})
}

func TestCachedCredentialsProvider_ExpirationTime(t *testing.T) {
	t.Run("CredsNil", func(t *testing.T) {
		opts := &CachedCredentialsProviderOptions{LogLevel: logo.DEBUG}
		p := NewCachedCredentialsProvider(new(AWSProfile), opts)
		if p.ExpirationTime() != time.Unix(0, 0) {
			t.Errorf("Expected nil credentials to have epoch expiration time, got :%v", p.ExpirationTime())
		}
	})

	t.Run("CredsValid", func(t *testing.T) {
		opts := &CachedCredentialsProviderOptions{LogLevel: logo.DEBUG}
		p := NewCachedCredentialsProvider(new(AWSProfile), opts)
		p.cacher = &credentialsCacher{file: "config/test/cached_creds_valid.json"}
		if p.ExpirationTime() == time.Unix(0, 0) {
			t.Errorf("Expected valid credentials to not have epoch expiration time, got :%v", p.ExpirationTime())
		}
	})
}
