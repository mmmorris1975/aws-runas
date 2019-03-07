package credentials

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/mmmorris1975/aws-runas/lib/cache"
	"time"
)

const (
	// SessionTokenProviderName is the name given to this AWS credential provider
	SessionTokenProviderName = "SessionTokenProvider"
	// SessionTokenMinDuration is the minimum allowed Session Token credential duration by the AWS API
	SessionTokenMinDuration = 15 * time.Minute
	// SessionTokenMaxDuration is the maximum allowed Session Token credential duration by the AWS API
	SessionTokenMaxDuration = 36 * time.Hour
	// SessionTokenDefaultDuration is a sensible default value for Session Token credential duration
	SessionTokenDefaultDuration = 12 * time.Hour
)

// SessionTokenProvider is the type to provide settings to perform the GetSessionToken operation in the AWS API.
// The provider borrows much from the AWS SDK AssumeRoleProvider as there is a number of common attributes between the
// two.  An optional Cache provides the ability to cache the credentials in order to limit API calls.
type SessionTokenProvider struct {
	credentials.Expiry
	// Allow an sts.STS object, or conforming mock object as a client
	client        stsiface.STSAPI
	cfg           *aws.Config
	log           aws.Logger
	Duration      time.Duration
	SerialNumber  string
	TokenCode     string
	TokenProvider func() (string, error)
	ExpiryWindow  time.Duration
	Cache         cache.CredentialCacher
}

// NewSessionCredentials configures a default SessionTokenProvider, and wraps it in an AWS credentials.Credentials object
// to allow Session Token credential fetching.  The default SessionTokenProvider uses the specified client.ConfigProvider to
// create a new sts.STS client, with the credential duration is set to SessionTokenDefaultDuration, and the ExpiryWindow
// is set to 10% of the duration value.  A list of options can be provided to add configuration to the SessionTokenProvider,
// such as overriding the Duration and ExpiryWindow, or specifying additional configuration like MFA SerialNumber.
func NewSessionCredentials(c client.ConfigProvider, options ...func(*SessionTokenProvider)) *credentials.Credentials {
	p := &SessionTokenProvider{
		client:       sts.New(c),
		cfg:          c.ClientConfig("sts").Config,
		Duration:     SessionTokenDefaultDuration,
		ExpiryWindow: SessionTokenDefaultDuration / 10,
	}

	for _, o := range options {
		o(p)
	}

	return credentials.NewCredentials(p)
}

// WithLogger configures a conforming Logger
func (s *SessionTokenProvider) WithLogger(l aws.Logger) *SessionTokenProvider {
	s.log = l
	return s
}

// Retrieve implements the AWS credentials.Provider interface to return a set of Session Token credentials.
// If the provider is configured to use a cache, it will be consulted to load the credentials.  If the credentials
// are expired, the credentials will be refreshed, and stored back in the cache.
func (s *SessionTokenProvider) Retrieve() (credentials.Value, error) {
	var cc *cache.CacheableCredentials
	var err error

	if s.Cache != nil {
		cc, err = s.Cache.Fetch()
		if err != nil {
			// Just mark as expired, and re-get the SessionToken creds from AWS
			// May want to log/notify that a failure happened, for troubleshooting
			s.Expiry.SetExpiration(time.Now(), SessionTokenMaxDuration)
		} else {
			s.debug("Found cached session token credentials")
			s.Expiry.SetExpiration(time.Unix(cc.Expiration, 0), s.ExpiryWindow)
		}
	}

	if s.IsExpired() {
		s.debug("Detected expired or unset session token credentials, refreshing")
		c, err := s.getSessionToken()
		if err != nil {
			return credentials.Value{}, err
		}

		cc = &cache.CacheableCredentials{
			Value: credentials.Value{
				AccessKeyID:     *c.AccessKeyId,
				SecretAccessKey: *c.SecretAccessKey,
				SessionToken:    *c.SessionToken,
				ProviderName:    SessionTokenProviderName,
			},
			Expiration: c.Expiration.Unix(),
		}

		if s.Cache != nil {
			if err := s.Cache.Store(cc); err != nil {
				s.debug("error caching credentials: %v", err)
			}
		}
	}

	s.debug("SESSION TOKEN CREDENTIALS: %+v", cc.Value)
	return cc.Value, nil
}

func (s *SessionTokenProvider) getSessionToken() (*sts.Credentials, error) {
	i := new(sts.GetSessionTokenInput).SetDurationSeconds(s.validateSessionDuration(s.Duration))
	if len(s.SerialNumber) > 0 {
		i.SerialNumber = &s.SerialNumber

		if len(s.TokenCode) < 1 {
			if s.TokenProvider != nil {
				t, err := s.TokenProvider()
				if err != nil {
					return nil, err
				}
				i.TokenCode = &t
			} else {
				return nil, fmt.Errorf("MFA required, but no code sent")
			}
		} else {
			i.TokenCode = &s.TokenCode
		}
	}

	o, err := s.client.GetSessionToken(i)
	if err != nil {
		return nil, err
	}
	s.Expiry.SetExpiration(*o.Credentials.Expiration, s.ExpiryWindow)

	return o.Credentials, nil
}

func (s *SessionTokenProvider) debug(f string, v ...interface{}) {
	if s.cfg != nil && s.cfg.LogLevel.AtLeast(aws.LogDebug) && s.log != nil {
		s.log.Log(fmt.Sprintf(f, v...))
	}
}

// Sanity check the requested duration, and fix if out of bounds
func (s *SessionTokenProvider) validateSessionDuration(d time.Duration) int64 {
	i := int64(d.Seconds())

	if d < SessionTokenMinDuration {
		s.debug("Session token duration too short")
		i = int64(SessionTokenMinDuration.Seconds())
	}

	if d > SessionTokenMaxDuration {
		s.debug("Session token duration too long")
		i = int64(SessionTokenMaxDuration.Seconds())
	}

	return i
}
