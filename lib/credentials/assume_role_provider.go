package credentials

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/mmmorris1975/aws-runas/lib/cache"
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

// AssumeRoleProvider is the type to provide settings to perform the Assume Role operation in the AWS API.
// This is purposely very similar to the AWS SDK AssumeRoleProvider, with the addition of an optional Cache to
// allow the ability to cache the credentials in order to limit API calls.
type AssumeRoleProvider struct {
	credentials.Expiry
	client          stscreds.AssumeRoler
	cfg             *aws.Config
	log             aws.Logger
	RoleARN         string
	RoleSessionName string
	ExternalID      string
	Duration        time.Duration
	SerialNumber    string
	TokenCode       string
	TokenProvider   func() (string, error)
	ExpiryWindow    time.Duration
	Cache           cache.CredentialCacher
}

// NewAssumeRoleCredentials configures a default AssumeRoleProvider, and wraps it in an AWS credentials.Credentials object
// to allow Assume Role credential fetching.  The default AssumeRoleProvides uses the specified client.ConfigProvider to
// create a new sts.STS client, and the provided roleArn as the role to assume; The credential duration is set to
// AssumeRoleDefaultDuration, and the ExpiryWindow is set to 10% of the duration value.  A list of options can be provided
// to add configuration to the AssumeRoleProvider, such as overriding the Duration and ExpiryWindow, or specifying additional
// Assume Role configuration like MFA SerialNumber of ExternalID.
func NewAssumeRoleCredentials(c client.ConfigProvider, roleArn string, options ...func(*AssumeRoleProvider)) *credentials.Credentials {
	p := &AssumeRoleProvider{
		client:       sts.New(c),
		cfg:          c.ClientConfig("sts").Config,
		RoleARN:      roleArn,
		Duration:     AssumeRoleDefaultDuration,
		ExpiryWindow: AssumeRoleDefaultDuration / 10,
	}

	for _, o := range options {
		o(p)
	}

	return credentials.NewCredentials(p)
}

// WithLogger configures a conforming Logger
func (p *AssumeRoleProvider) WithLogger(l aws.Logger) *AssumeRoleProvider {
	p.log = l
	return p
}

// Retrieve implements the AWS credentials.Provider interface to return a set of Assume Role credentials.
// If the provider is configured to use a cache, it will be consulted to load the credentials.  If the credentials
// are expired, the credentials will be refreshed, and stored back in the cache.
func (p *AssumeRoleProvider) Retrieve() (credentials.Value, error) {
	var cc *cache.CacheableCredentials
	var err error

	if p.Cache != nil {
		cc, err = p.Cache.Fetch()
		if err != nil {
			// Just mark as expired, and re-get the SessionToken creds from AWS
			// May want to log/notify that a failure happened, for troubleshooting
			p.Expiry.SetExpiration(time.Now(), SessionTokenMaxDuration)
		} else {
			p.debug("Found cached assume role credentials")
			p.Expiry.SetExpiration(time.Unix(cc.Expiration, 0), p.ExpiryWindow)
		}
	}

	if p.IsExpired() {
		p.debug("Detected expired or unset assume role credentials, refreshing")
		c, err := p.assumeRole()
		if err != nil {
			return credentials.Value{}, err
		}

		cc = &cache.CacheableCredentials{
			Value: credentials.Value{
				AccessKeyID:     *c.AccessKeyId,
				SecretAccessKey: *c.SecretAccessKey,
				SessionToken:    *c.SessionToken,
				ProviderName:    AssumeRoleProviderName,
			},
			Expiration: c.Expiration.Unix(),
		}

		if p.Cache != nil {
			if err := p.Cache.Store(cc); err != nil {
				p.debug("error caching credentials: %v", err)
			}
		}
	}

	p.debug("ASSUME ROLE CREDENTIALS: %+v", cc.Value)
	return cc.Value, nil
}

func (p *AssumeRoleProvider) assumeRole() (*sts.Credentials, error) {
	i := new(sts.AssumeRoleInput).SetDurationSeconds(p.validateDuration(p.Duration)).SetRoleArn(p.RoleARN).
		SetRoleSessionName(p.RoleSessionName)

	if len(p.ExternalID) > 0 {
		i.ExternalId = aws.String(p.ExternalID)
	}

	if len(p.SerialNumber) > 0 {
		i.SerialNumber = aws.String(p.SerialNumber)

		if len(p.TokenCode) < 1 {
			if p.TokenProvider != nil {
				t, err := p.TokenProvider()
				if err != nil {
					return nil, err
				}
				i.TokenCode = &t
			} else {
				return nil, fmt.Errorf("MFA required, but no code sent")
			}
		} else {
			i.TokenCode = aws.String(p.TokenCode)
		}
	}

	o, err := p.AssumeRole(i)
	if err != nil {
		return nil, err
	}
	p.Expiry.SetExpiration(*o.Credentials.Expiration, p.ExpiryWindow)
	return o.Credentials, nil
}

// AssumeRole implements the AssumeRoler interface, calling the AssumeRole method on the underlying client
// using the provided AssumeRoleInput
func (p *AssumeRoleProvider) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	return p.client.AssumeRole(input)
}

func (p *AssumeRoleProvider) debug(f string, v ...interface{}) {
	if p.cfg != nil && p.cfg.LogLevel.AtLeast(aws.LogDebug) {
		p.log.Log(fmt.Sprintf(f, v...))
	}
}

// StdinTokenProvider will print a prompt to Stdout for a user to enter the MFA code
func StdinTokenProvider() (string, error) {
	var mfaCode string
	fmt.Print("Enter MFA Code: ")
	_, err := fmt.Scanln(&mfaCode)
	return mfaCode, err
}

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
