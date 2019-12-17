package credentials

import (
	"aws-runas/lib/cache"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
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

// SessionTokenProvider provides the settings to perform the GetSessionToken operation in the AWS API.
// An optional Cache provides the ability to cache the credentials in order to limit API calls.
type SessionTokenProvider struct {
	*stsCredentialProvider
}

// NewSessionCredentials configures a default SessionTokenProvider, and wraps it in an AWS credentials.Credentials object
// to allow Session Token credential fetching.  The default SessionTokenProvider uses the specified client.ConfigProvider to
// create a new sts.STS client, with the credential duration is set to SessionTokenDefaultDuration, and the ExpiryWindow
// is set to 10% of the duration value.  A list of options can be provided to add configuration to the SessionTokenProvider,
// such as overriding the Duration and ExpiryWindow, or specifying additional configuration like MFA SerialNumber.
func NewSessionTokenCredentials(cfg client.ConfigProvider, options ...func(*SessionTokenProvider)) *credentials.Credentials {
	p := &SessionTokenProvider{newStsCredentialProvider(cfg)}
	p.Duration = SessionTokenDefaultDuration
	p.ExpiryWindow = p.Duration / 10

	for _, o := range options {
		o(p)
	}

	return credentials.NewCredentials(p)
}

// Retrieve implements the AWS credentials.Provider interface to return a set of Session Token credentials.
// If the provider is configured to use a cache, it will be consulted to load the credentials.  If the credentials
// are expired, the credentials will be refreshed, and stored back in the cache.
func (p *SessionTokenProvider) Retrieve() (credentials.Value, error) {
	var err error
	creds := p.checkCache()

	if p.IsExpired() {
		p.debug("Detected expired or unset session token credentials, refreshing")
		creds, err = p.retrieve()
		if err != nil {
			return credentials.Value{}, err
		}

		if p.Cache != nil {
			if err := p.Cache.Store(creds); err != nil {
				p.debug("error caching credentials: %v", err)
			}
		}
	}

	if creds == nil {
		// something's wacky, expire existing provider creds, and retry
		p.SetExpiration(time.Unix(0, 0), 0)
		return p.Retrieve()
	}

	v := creds.Value(SessionTokenProviderName)

	p.debug("SESSION TOKEN CREDENTIALS: %+v", v)
	return v, nil
}

func (p *SessionTokenProvider) retrieve() (*cache.CacheableCredentials, error) {
	if p.Duration == 0 {
		p.Duration = SessionTokenDefaultDuration
	}

	i := new(sts.GetSessionTokenInput).SetDurationSeconds(p.validateSessionDuration(p.Duration))

	t, err := p.handleMfa()
	if err != nil {
		return nil, err
	}

	if len(p.SerialNumber) > 0 {
		i.SerialNumber = &p.SerialNumber
		i.TokenCode = t
	}

	o, err := p.client.GetSessionToken(i)
	if err != nil {
		return nil, err
	}
	p.Expiry.SetExpiration(*o.Credentials.Expiration, p.ExpiryWindow)

	c := cache.CacheableCredentials(*o.Credentials)
	return &c, nil
}

// Sanity check the requested duration, and fix if out of bounds.  The returned value is the accepted type for the
// SetDurationSeconds() setting for the AWS credential request
func (p *SessionTokenProvider) validateSessionDuration(d time.Duration) int64 {
	i := int64(d.Seconds())

	if d < SessionTokenMinDuration {
		p.debug("Session token duration too short")
		i = int64(SessionTokenMinDuration.Seconds())
	}

	if d > SessionTokenMaxDuration {
		p.debug("Session token duration too long")
		i = int64(SessionTokenMaxDuration.Seconds())
	}

	return i
}
