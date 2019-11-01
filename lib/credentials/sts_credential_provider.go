package credentials

import (
	"aws-runas/lib/cache"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"time"
)

type stsCredentialProvider struct {
	credentials.Expiry
	client        stsiface.STSAPI
	cfg           *aws.Config
	Cache         cache.CredentialCacher
	Duration      time.Duration
	ExpiryWindow  time.Duration
	Log           aws.Logger
	SerialNumber  string
	TokenCode     string
	TokenProvider func() (string, error)
}

func newStsCredentialProvider(c client.ConfigProvider) *stsCredentialProvider {
	return &stsCredentialProvider{
		client:        sts.New(c),
		cfg:           c.ClientConfig("sts").Config,
		Log:           aws.NewDefaultLogger(),
		TokenProvider: StdinMfaTokenProvider,
	}
}

func (p *stsCredentialProvider) checkCache() *cache.CacheableCredentials {
	var creds *cache.CacheableCredentials

	if p.Cache != nil {
		var err error
		creds, err = p.Cache.Load()
		if err != nil {
			p.SetExpiration(time.Now(), SessionTokenMaxDuration)
		} else {
			p.SetExpiration(*creds.Expiration, p.Duration)
		}
	}

	return creds
}

func (p *stsCredentialProvider) handleMfa() (*string, error) {
	if len(p.SerialNumber) > 0 && len(p.TokenCode) < 1 {
		if p.TokenProvider != nil {
			t, err := p.TokenProvider()
			if err != nil {
				return nil, err
			}
			p.TokenCode = t
		} else {
			return nil, fmt.Errorf("MFA required, but no code sent")
		}
	}

	if len(p.TokenCode) > 0 {
		return &p.TokenCode, nil
	}
	return nil, nil
}

func (p *stsCredentialProvider) debug(f string, v ...interface{}) {
	if p.cfg != nil && p.cfg.LogLevel.AtLeast(aws.LogDebug) && p.Log != nil {
		p.Log.Log(fmt.Sprintf(f, v...))
	}
}
