package credentials

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
)

const (
	// WebRoleProviderName is the name given to this AWS credential provider.
	WebRoleProviderName = "WebIdentityRoleProvider"
)

// webRoleProvider contains the settings to perform the AssumeRoleWithWebIdentity operation in the AWS API.
// An optional Cache provides the ability to cache the credentials in order to limit API calls.
type webRoleProvider struct {
	*AssumeRoleProvider
	webIdentityToken *OidcIdentityToken
}

// NewWebRoleProvider configures a default webRoleProvider to allow Assume Role using Oauth2/OIDC.  The default provider
// uses the specified client.ConfigProvider to create a new sts.STS client, the roleArn argument as the role to assume,
// and token is the web identity token which was returned after performing the necessary operations against the
// identity provider. The credential duration is set to AssumeRoleDefaultDuration, and the ExpiryWindow is set to 10% of
// the duration value.
func NewWebRoleProvider(cfg client.ConfigProvider, roleArn string) *webRoleProvider {
	return &webRoleProvider{AssumeRoleProvider: NewAssumeRoleProvider(cfg, roleArn)}
}

// WebIdentityToken is the implementation of the WebRoleProvider interface for setting the Web (OIDC) Identity Token
// used for the Assume Role with Web Identity operation.
func (p *webRoleProvider) WebIdentityToken(token *OidcIdentityToken) {
	p.webIdentityToken = token
}

// Retrieve implements the AWS credentials.Provider interface to return a set of Assume Role with Web Identity credentials.
// If the provider is configured to use a cache, it will be consulted to load the credentials.  If the credentials
// are expired, the credentials will be refreshed, and stored back in the cache.
func (p *webRoleProvider) Retrieve() (credentials.Value, error) {
	return p.RetrieveWithContext(aws.BackgroundContext())
}

// RetrieveWithContext implements the AWS credentials.ProviderWithContext interface to return a set of Assume Role with
// Web Identity credentials, using the provided context argument.  If the provider is configured to use a cache, it will
// be consulted to load the credentials.  If the credentials are expired, the credentials will be refreshed, and stored
// back in the cache.
func (p *webRoleProvider) RetrieveWithContext(ctx aws.Context) (credentials.Value, error) {
	var err error
	creds := p.CheckCache()

	if p.IsExpired() {
		p.Logger.Debugf("Detected expired or unset web identity role credentials, refreshing")
		creds, err = p.retrieve(ctx)
		if err != nil {
			return credentials.Value{}, err
		}

		if p.Cache != nil {
			if err := p.Cache.Store(creds); err != nil {
				p.Logger.Debugf("error caching credentials: %v", err)
			}
		}
	}

	// afaik, this can never happen
	// if creds == nil {
	//	// something's wacky, expire existing provider creds, and retry
	//	p.SetExpiration(time.Unix(0, 0), 0)
	//	return p.Retrieve()
	// }

	v := creds.Value()
	v.ProviderName = WebRoleProviderName

	p.Logger.Debugf("WEB IDENTITY ROLE CREDENTIALS: %+v", v)
	return v, nil
}

func (p *webRoleProvider) retrieve(ctx aws.Context) (*Credentials, error) {
	in, err := p.getAssumeRoleWithWebIdentityInput()
	if err != nil {
		return nil, err
	}

	out, err := p.Client.AssumeRoleWithWebIdentityWithContext(ctx, in)
	if err != nil {
		return nil, err
	}

	if p.ExpiryWindow < 1 {
		p.ExpiryWindow = p.Duration / 10
	}
	p.SetExpiration(*out.Credentials.Expiration, p.ExpiryWindow)

	c := FromStsCredentials(out.Credentials)
	return c, nil
}

func (p *webRoleProvider) getAssumeRoleWithWebIdentityInput() (*sts.AssumeRoleWithWebIdentityInput, error) {
	if len(p.webIdentityToken.String()) < 4 {
		// AWS says this must be at least 4 chars long to be valid
		return nil, errors.New("invalid WebIdentity Token detected, check your local setup and identity provider configuration")
	}

	in := &sts.AssumeRoleWithWebIdentityInput{
		DurationSeconds:  p.ConvertDuration(p.Duration, AssumeRoleDurationMin, AssumeRoleDurationMax, AssumeRoleDurationDefault),
		RoleArn:          aws.String(p.RoleArn),
		WebIdentityToken: aws.String(p.webIdentityToken.String()),
	}

	if len(p.RoleSessionName) > 0 {
		in.RoleSessionName = aws.String(p.RoleSessionName)
	}

	return in, nil
}

func (p *webRoleProvider) ClearCache() error {
	if p.Cache != nil {
		p.Logger.Debugf("clearing cached web identity role credentials")
		return p.Cache.Clear()
	}
	return nil
}
