package lib

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/mbndr/logo"
	"os"
	"time"
)

const (
	// AWS SDK minimum session token duration
	SESSION_TOKEN_MIN_DURATION = time.Duration(15 * time.Minute)
	// AWS SDK maximum session token duration
	SESSION_TOKEN_MAX_DURATION = time.Duration(36 * time.Hour)
	// AWS SDK default session token duration
	SESSION_TOKEN_DEFAULT_DURATION = time.Duration(12 * time.Hour)
)

// Interface defining the methods needed to manage AWS session token credentials
type SessionTokenProvider interface {
	credentials.Provider
}

type sessionTokenProvider struct {
	CachedCredentialsProvider
}

// Create a new SessionTokenProvider for the given profile. Unspecified
// credential durations will be set to their default value. Values outside
// of the min and max range will be set to the respective min/max values.
//
// If the MfaSerial option is provided, its value will be provided to the
// call to create the session token credentials.  This value will override
// any value set in the profile.
//
// The credential cache file will reside in the directory for the default
// config file name, with a file name of .aws_session_token_<profile>
func NewSessionTokenProvider(profile *AWSProfile, opts *CachedCredentialsProviderOptions) SessionTokenProvider {
	p := new(sessionTokenProvider)
	p.providerName = "SessionTokenProvider"

	if opts == nil {
		opts = new(CachedCredentialsProviderOptions)
	}
	opts.cacheFilePrefix = ".aws_session_token"
	p.log = logo.NewSimpleLogger(os.Stderr, opts.LogLevel, "aws-runas.SessionTokenProvider", true)

	p.CachedCredentialsProvider = NewCachedCredentialsProvider(profile, opts)

	return p
}

// Check if a set of credentials have expired (or are within the
// expiration window).  Default case is to return true so that only
// verified non-expired credentials will report as not expired.
//
// satisfies credentials.Provider
//func (p *sessionTokenProvider) IsExpired() bool {
//	c := p.creds
//	if c == nil {
//		p.log.Debugf("No credentials loaded, returning expired = true")
//		return true
//	}
//
//	stat, err := os.Stat(p.cacher.CacheFile())
//	if err == nil {
//		expTime := time.Unix(c.Expiration, 0)
//		window := expTime.Sub(stat.ModTime()) / 10
//		c.SetExpiration(expTime, window)
//	} else {
//		p.log.Debugf("Error calling Stat() on credential cache file: %v", err)
//	}
//
//	return c.IsExpired()
//}

// Retrieve the session token credentials from the cache.  If the
// credentials are expired, or there is no cache, a new set of
// session token credentials will be created and stored.
//
// On error, the error return value will be non-nil with an empty
// credentials.Value
//
// satisfies credentials.Provider
func (p *sessionTokenProvider) Retrieve() (credentials.Value, error) {
	// lazy load credentials
	c, err := p.cacher.Fetch()
	if err == nil {
		p.log.Debugf("Found cached session token credentials")
		p.creds = c
	}

	if p.IsExpired() {
		p.log.Debugf("Detected expired or unset session token credentials, refreshing")
		creds, err := p.getSessionToken()
		if err != nil {
			return credentials.Value{}, err
		}

		c = &CachableCredentials{
			Expiration: creds.Expiration.Unix(),
			Value: credentials.Value{
				AccessKeyID:     *creds.AccessKeyId,
				SecretAccessKey: *creds.SecretAccessKey,
				SessionToken:    *creds.SessionToken,
				ProviderName:    p.providerName,
			},
		}
		p.creds = c
		p.cacher.Store(c)
	}

	p.log.Debugf("SESSION TOKEN CREDENTIALS: %+v", p.creds)
	return p.creds.Value, nil
}

func (p *sessionTokenProvider) getSessionToken() (*sts.Credentials, error) {
	d := p.opts.CredentialDuration
	if d < 1 {
		p.log.Debug("Setting default session token duration")
		d = SESSION_TOKEN_DEFAULT_DURATION
	} else if d < SESSION_TOKEN_MIN_DURATION {
		p.log.Debug("Session token duration too short, adjusting to min value")
		d = SESSION_TOKEN_MIN_DURATION
	} else if d > SESSION_TOKEN_MAX_DURATION {
		p.log.Debug("Session token duration too long, adjusting to max value")
		d = SESSION_TOKEN_MAX_DURATION
	}

	in := new(sts.GetSessionTokenInput)
	in.DurationSeconds = aws.Int64(int64(d.Seconds()))

	if len(p.opts.MfaSerial) > 0 {
		in.SerialNumber = aws.String(p.opts.MfaSerial)
		in.TokenCode = aws.String(PromptForMfa())
	}

	s := sts.New(p.sess)
	res, err := s.GetSessionToken(in)
	if err != nil {
		return nil, err
	}
	return res.Credentials, nil
}
