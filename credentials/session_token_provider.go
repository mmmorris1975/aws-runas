package credentials

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"time"
)

const (
	// SessionTokenProviderName is the name given to this AWS credential provider.
	SessionTokenProviderName = "SessionTokenProvider"
	// SessionTokenDurationMin is the minimum allowed Session Token credential duration by the AWS API.
	SessionTokenDurationMin = 15 * time.Minute
	// SessionTokenDurationMax is the maximum allowed Session Token credential duration by the AWS API.
	SessionTokenDurationMax = 36 * time.Hour
	// SessionTokenDurationDefault is a sensible default value for Session Token credential duration.
	SessionTokenDurationDefault = 12 * time.Hour
)

// SessionTokenProvider provides the settings to perform the GetSessionToken operation in the AWS API.
// An optional Cache provides the ability to cache the credentials in order to limit API calls.
type SessionTokenProvider struct {
	*baseStsProvider
}

// NewSessionTokenProvider configures a default SessionTokenProvider to allow retrieval of Session Token credentials.
// The default provider uses the specified client.ConfigProvider to create a new sts.STS client. The credential duration
// is set to SessionTokenDurationDefault, and the ExpiryWindow is set to 10% of the duration value.
func NewSessionTokenProvider(cfg aws.Config) *SessionTokenProvider {
	b := newBaseStsProvider(cfg)
	b.Duration = SessionTokenDurationDefault
	b.ExpiryWindow = -1

	return &SessionTokenProvider{b}
}

// RetrieveWithContext implements the AWS credentials.ProviderWithContext interface to return a set of Session Token
// credentials, using the provided context argument.  If the provider is configured to use a cache, it will be
// consulted to load the credentials.  If the credentials are expired, the credentials will be refreshed (prompting for
// MFA, if necessary), and stored back in the cache.
func (p *SessionTokenProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	var err error
	creds := p.CheckCache()

	if creds == nil || creds.Value().Expired() {
		p.Logger.Debugf("Detected expired or unset session token credentials, refreshing")
		creds, err = p.retrieve(ctx)
		if err != nil {
			return aws.Credentials{}, err
		}

		if p.Cache != nil {
			if err = p.Cache.Store(creds); err != nil {
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
	v.Source = SessionTokenProviderName

	p.Logger.Debugf("SESSION TOKEN CREDENTIALS: %+v", v)
	return v, nil
}

func (p *SessionTokenProvider) retrieve(ctx context.Context) (*Credentials, error) {
	in, err := p.getSessionTokenInput()
	if err != nil {
		return nil, err
	}

	out, err := p.Client.GetSessionToken(ctx, in)
	if err != nil {
		return nil, err
	}

	if p.ExpiryWindow < 1 {
		p.ExpiryWindow = p.Duration / 10
	}

	c := FromStsCredentials(out.Credentials)
	c.Expiration = *out.Credentials.Expiration
	return c, nil
}

func (p *SessionTokenProvider) getSessionTokenInput() (*sts.GetSessionTokenInput, error) {
	in := new(sts.GetSessionTokenInput)
	in.DurationSeconds = p.ConvertDuration(p.Duration, SessionTokenDurationMin, SessionTokenDurationMax, SessionTokenDurationDefault)

	if len(p.SerialNumber) > 0 {
		in.SerialNumber = aws.String(p.SerialNumber)
	}

	code, err := p.handleMfa()
	if err != nil {
		return nil, err
	}
	in.TokenCode = code

	return in, nil
}
