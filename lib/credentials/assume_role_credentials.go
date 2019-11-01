package credentials

import (
	"aws-runas/lib/cache"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
	"time"
)

const (
	// AssumeRoleProviderName is the name given to this AWS credential provider
	AssumeRoleProviderName = "AssumeRoleProvider"
	// AssumeRoleMinDuration is the minimum allowed Assume Role credential duration by the AWS API
	AssumeRoleMinDuration = 15 * time.Minute
	// AssumeRoleMaxDuration is the maximum allowed Assume Role credential duration by the AWS API
	AssumeRoleMaxDuration = 12 * time.Hour
	// AssumeRoleDefaultDuration is a sensible default value for Assume Role credential duration
	AssumeRoleDefaultDuration = 1 * time.Hour
)

// AssumeRoleProvider provides the settings to perform the AssumeRole operation in the AWS API.
// An optional Cache provides the ability to cache the credentials in order to limit API calls.
type AssumeRoleProvider struct {
	*stsCredentialProvider
	RoleARN         string
	RoleSessionName string
	ExternalID      string
}

// NewAssumeRoleCredentials configures a default AssumeRoleProvider, and wraps it in an AWS credentials.Credentials object
// to allow Assume Role credential fetching.  The default AssumeRoleProvider uses the specified client.ConfigProvider to
// create a new sts.STS client, and the provided roleArn as the role to assume; The credential duration is set to
// AssumeRoleDefaultDuration, and the ExpiryWindow is set to 10% of the duration value.  A list of options can be provided
// to add configuration to the AssumeRoleProvider, such as overriding the Duration and ExpiryWindow, or specifying additional
// Assume Role configuration like MFA SerialNumber of ExternalID.
func NewAssumeRoleCredentials(cfg client.ConfigProvider, roleArn string, options ...func(*AssumeRoleProvider)) *credentials.Credentials {
	p := &AssumeRoleProvider{stsCredentialProvider: newStsCredentialProvider(cfg), RoleARN: roleArn}
	p.Duration = AssumeRoleDefaultDuration
	p.ExpiryWindow = p.Duration / 10

	for _, o := range options {
		o(p)
	}

	return credentials.NewCredentials(p)
}

// Retrieve implements the AWS credentials.Provider interface to return a set of Assume Role credentials.
// If the provider is configured to use a cache, it will be consulted to load the credentials.  If the credentials
// are expired, the credentials will be refreshed, and stored back in the cache.
func (p *AssumeRoleProvider) Retrieve() (credentials.Value, error) {
	var err error
	creds := p.checkCache()

	if p.IsExpired() {
		p.debug("Detected expired or unset assume role credentials, refreshing")
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

	v := creds.Value(AssumeRoleProviderName)

	p.debug("ASSUME ROLE CREDENTIALS: %+v", v)
	return v, nil
}

func (p *AssumeRoleProvider) retrieve() (*cache.CacheableCredentials, error) {
	i := new(sts.AssumeRoleInput).SetDurationSeconds(p.validateDuration(p.Duration)).SetRoleArn(p.RoleARN).
		SetRoleSessionName(p.RoleSessionName)

	if len(p.ExternalID) > 0 {
		i.ExternalId = aws.String(p.ExternalID)
	}

	t, err := p.handleMfa()
	if err != nil {
		return nil, err
	}

	if len(p.SerialNumber) > 0 {
		i.SerialNumber = &p.SerialNumber
		i.TokenCode = t
	}

	o, err := p.AssumeRole(i)
	if err != nil {
		return nil, err
	}
	p.Expiry.SetExpiration(*o.Credentials.Expiration, p.ExpiryWindow)

	c := cache.CacheableCredentials(*o.Credentials)
	return &c, nil
}

// AssumeRole implements the AssumeRoler interface, calling the AssumeRole method on the underlying client
// using the provided AssumeRoleInput
func (p *AssumeRoleProvider) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	return p.client.AssumeRole(input)
}

// Sanity check the requested duration, and fix if out of bounds.  The returned value is the accepted type for the
// SetDurationSeconds() setting for the AWS credential request
func (p *AssumeRoleProvider) validateDuration(d time.Duration) int64 {
	s := int64(d.Seconds())

	if d < AssumeRoleMinDuration {
		p.debug("Assume role duration too short")
		s = int64(AssumeRoleMinDuration.Seconds())
	}

	if d > AssumeRoleMaxDuration {
		p.debug("Assume role duration too long")
		s = int64(AssumeRoleMaxDuration.Seconds())
	}

	return s
}
