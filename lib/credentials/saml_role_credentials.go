package credentials

import (
	"aws-runas/lib/cache"
	"encoding/base64"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
	"regexp"
	"strings"
	"time"
)

const (
	// SamlRoleProviderName is the name given to this AWS credential provider
	SamlRoleProviderName = "SamlRoleProvider"
)

// SamlRoleProvider provides the settings to perform the AssumeRoleWithSAML operation in the AWS API.
// An optional Cache provides the ability to cache the credentials in order to limit API calls.
type SamlRoleProvider struct {
	*AssumeRoleProvider
	principalArn  string
	SAMLAssertion string
}

// NewSAMLRoleCredentials configures a default SamlRoleProvider, and wraps it in an AWS credentials.Credentials object
// to allow Assume Role with SAML credential fetching.  The default provider uses the specified client.ConfigProvider to
// create a new sts.STS client, and the provided roleArn as the role to assume; The credential duration is set to
// AssumeRoleDefaultDuration, and the ExpiryWindow is set to 10% of the duration value.  A list of options can be provided
// to add configuration to the SamlRoleProvider, such as overriding the Duration and ExpiryWindow, or specifying additional
// Assume Role with SAML configuration like Principal ARN or the SAML assertion.
func NewSamlRoleCredentials(cfg client.ConfigProvider, roleArn string, saml string, options ...func(*SamlRoleProvider)) *credentials.Credentials {
	p := new(SamlRoleProvider)
	p.AssumeRoleProvider = &AssumeRoleProvider{stsCredentialProvider: newStsCredentialProvider(cfg), RoleARN: roleArn}
	p.Duration = AssumeRoleDefaultDuration
	p.ExpiryWindow = p.Duration / 10
	p.SAMLAssertion = saml

	for _, o := range options {
		o(p)
	}

	p.setPrincipalArn()

	return credentials.NewCredentials(p)
}

// Retrieve implements the AWS credentials.Provider interface to return a set of Assume Role with SAML credentials.
// If the provider is configured to use a cache, it will be consulted to load the credentials.  If the credentials
// are expired, the credentials will be refreshed, and stored back in the cache.
func (p *SamlRoleProvider) Retrieve() (credentials.Value, error) {
	var err error
	creds := p.checkCache()

	if p.IsExpired() {
		p.debug("Detected expired or unset saml role credentials, refreshing")
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

	v := creds.Value(SamlRoleProviderName)

	p.debug("SAML ROLE CREDENTIALS: %+v", v)
	return v, nil
}

func (p *SamlRoleProvider) retrieve() (*cache.CacheableCredentials, error) {
	if p.Duration < 1 {
		p.Duration = AssumeRoleDefaultDuration
	}

	i := new(sts.AssumeRoleWithSAMLInput).SetDurationSeconds(p.validateDuration(p.Duration)).SetRoleArn(p.RoleARN).
		SetPrincipalArn(p.principalArn).SetSAMLAssertion(p.SAMLAssertion)

	// unlike plain AssumeRole, we don't (can't!) check MFA with the SAML request
	o, err := p.client.AssumeRoleWithSAML(i)
	if err != nil {
		return nil, err
	}
	p.Expiry.SetExpiration(*o.Credentials.Expiration, p.ExpiryWindow)

	c := cache.CacheableCredentials(*o.Credentials)
	return &c, nil
}

func (p *SamlRoleProvider) setPrincipalArn() {
	re, err := regexp.Compile(`>(arn:aws:iam::\d+:role/.*?),(arn:aws:iam::\d+:saml-provider/.*?)<`)
	if err != nil {
		return
	}

	d, err := base64.StdEncoding.DecodeString(p.SAMLAssertion)
	if err != nil {
		return
	}

	m := re.FindAllStringSubmatch(string(d), -1)
	if m != nil {
		for _, r := range m {
			if strings.EqualFold(r[1], p.RoleARN) {
				p.principalArn = r[2]
				return
			}
		}
	}
}
