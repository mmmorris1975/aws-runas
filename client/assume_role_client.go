package client

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/client"
	awscreds "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/mmmorris1975/aws-runas/credentials"
	"os/user"
	"time"
)

type assumeRoleClient struct {
	*baseIamClient
	provider *credentials.AssumeRoleProvider
}

// AssumeRoleClientConfig is the configuration attributes for the STS Assume Role operation for either IAM identities,
// or role chaining using SAML or OIDC Identity Tokens.
type AssumeRoleClientConfig struct {
	SessionTokenClientConfig
	RoleArn         string
	RoleSessionName string
	ExternalId      string
}

// NewAssumeRoleClient is an AwsClient which knows how to do Assume Role operations.
func NewAssumeRoleClient(cfg client.ConfigProvider, clientCfg *AssumeRoleClientConfig) *assumeRoleClient {
	c := &assumeRoleClient{newBaseIamClient(cfg, clientCfg.Logger), nil}

	p := credentials.NewAssumeRoleProvider(cfg, clientCfg.RoleArn)
	p.Cache = clientCfg.Cache
	p.Duration = clientCfg.Duration
	p.SerialNumber = clientCfg.SerialNumber
	p.TokenCode = clientCfg.TokenCode
	p.TokenProvider = clientCfg.TokenProvider
	p.ExternalId = clientCfg.ExternalId
	p.RoleSessionName = clientCfg.RoleSessionName
	p.Logger = clientCfg.Logger

	if len(p.RoleSessionName) < 2 { // AWS SDK minimum length
		if id, err := c.ident.Identity(); err == nil {
			p.RoleSessionName = id.Username
		} else if usr, err := user.Current(); err == nil {
			p.RoleSessionName = usr.Username
		} else {
			// escape route value ... matches AWS SDK value defaulting logic
			p.RoleSessionName = fmt.Sprintf("%d", time.Now().UTC().UnixNano())
		}
	}

	c.provider = p
	c.creds = awscreds.NewCredentials(p)
	return c
}

// ClearCache cleans the cache for this client's AWS credential cache.
func (c *assumeRoleClient) ClearCache() error {
	if c.provider.Cache != nil {
		c.provider.Logger.Debugf("clearing cached assume role credentials")
		return c.provider.Cache.Clear()
	}
	return nil
}
