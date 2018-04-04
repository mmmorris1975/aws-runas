package lib

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/mbndr/logo"
	"os"
	"path/filepath"
	"time"
)

type CachedCredentialProvider interface {
	CacheFile() string
	ExpirationTime() time.Time
}

// Options applicable to all kinds of CachedCredentialsProviders
type CachedCredentialsProviderOptions struct {
	LogLevel           logo.Level
	CredentialDuration time.Duration
	MfaSerial          string
	cacheFileName      string
}

type cachedCredentialsProvider struct {
	providerName string
	profile      *AWSProfile
	log          *logo.Logger
	creds        *CachableCredentials
	opts         *CachedCredentialsProviderOptions
	sess         *session.Session
	cacher       CredentialsCacher
}

// Create a new CachedCredentialsProvider for the given profile.
// The returned value is the base type for building other, more sophisticated
// credential.Providers
func NewCachedCredentialsProvider(profile *AWSProfile, opts *CachedCredentialsProviderOptions) cachedCredentialsProvider {
	if profile == nil {
		panic("invalid profile argument to NewCachedCredentialsProvider")
	}
	if opts == nil {
		opts = new(CachedCredentialsProviderOptions)
	}

	prof := profile.Name
	if len(profile.SourceProfile) > 0 {
		prof = profile.SourceProfile
	}

	file := opts.cacheFileName
	if len(file) < 1 {
		file = fmt.Sprintf(".aws_cached_credentials_%s", prof)
	}

	p := new(cachedCredentialsProvider)
	p.profile = profile
	p.opts = opts
	p.sess = AwsSession(prof)

	cacheDir := filepath.Dir(AwsConfigFile())
	cacheFile := filepath.Join(cacheDir, file)
	cacheOpts := new(CredentialsCacherOptions)
	cacheOpts.LogLevel = opts.LogLevel

	p.cacher = NewCredentialsCacher(cacheFile, cacheOpts)

	return *p
}

// Check if a set of credentials have expired (or are within the
// expiration window).  Default case is to return true so that only
// verified non-expired credentials will report as not expired.
//
// satisfies credentials.Provider
func (p *cachedCredentialsProvider) IsExpired() bool {
	c, err := p.cacher.Fetch()
	if c == nil || err != nil {
		if p.log != nil {
			p.log.Debugf("No credentials loaded, returning expired = true")
		}
		return true
	}

	stat, err := os.Stat(p.cacher.CacheFile())
	if err == nil {
		expTime := time.Unix(c.Expiration, 0)
		window := expTime.Sub(stat.ModTime()) / 10
		c.SetExpiration(expTime, window)
	} else {
		if p.log != nil {
			p.log.Debugf("Error calling Stat() on credential cache file: %v", err)
		}
	}

	return c.IsExpired()
}

func (p *cachedCredentialsProvider) CacheFile() string {
	return p.cacher.CacheFile()
}

func (p *cachedCredentialsProvider) ExpirationTime() time.Time {
	c := p.creds
	if c == nil {
		if p.log != nil {
			p.log.Debugf("No credentials set, returning epoch time")
		}
		return time.Unix(0, 0)
	}
	return time.Unix(c.Expiration, 0)
}
