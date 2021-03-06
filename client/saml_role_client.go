package client

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/mmmorris1975/aws-runas/client/external"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
	"time"
)

type samlRoleClient struct {
	samlClient   external.SamlClient
	roleProvider credentials.SamlRoleProvider
	session      aws.Config
}

// SamlRoleClientConfig is the means to specify the configuration for the Assume Role with SAML operation.  This includes
// information necessary to communicate with the external IdP, as well as the configuration for the AWS API calls.
type SamlRoleClientConfig struct {
	external.AuthenticationClientConfig
	Cache    credentials.CredentialCacher
	Duration time.Duration
	RoleArn  string
}

// NewSamlRoleClient returns a new SAML aware AwsClient for obtaining identity information from the external IdP, and
// for making the AWS Assume Role with SAML API call.
func NewSamlRoleClient(cfg aws.Config, url string, clientCfg *SamlRoleClientConfig) *samlRoleClient {
	p := credentials.NewSamlRoleProvider(cfg, clientCfg.RoleArn, new(credentials.SamlAssertion))
	p.Duration = clientCfg.Duration
	p.Cache = clientCfg.Cache
	p.Logger = clientCfg.Logger

	cfg.Credentials = p

	return &samlRoleClient{
		samlClient:   external.MustGetSamlClient(clientCfg.IdentityProviderName, url, clientCfg.AuthenticationClientConfig),
		roleProvider: p,
		session:      cfg,
	}
}

// Identity is the implementation of the IdentityClient interface for retrieving identity information from the external IdP.
func (c *samlRoleClient) Identity() (*identity.Identity, error) {
	return c.samlClient.Identity()
}

// Roles is the implementation of the IdentityClient interface for retrieving IAM role information from the external IdP.
func (c *samlRoleClient) Roles() (*identity.Roles, error) {
	return c.samlClient.Roles()
}

// Credentials is the implementation of the CredentialClient interface, and calls CredentialsWithContext with a
// background context.
func (c *samlRoleClient) Credentials() (*credentials.Credentials, error) {
	return c.CredentialsWithContext(context.Background())
}

// CredentialsWithContext is the implementation of the CredentialClient interface for retrieving temporary AWS
// credentials using the Assume Role with SAML operation.
func (c *samlRoleClient) CredentialsWithContext(ctx context.Context) (*credentials.Credentials, error) {
	saml, err := c.samlClient.SamlAssertion()
	if err != nil {
		return nil, err
	}
	c.roleProvider.SamlAssertion(saml)

	v, err := c.roleProvider.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	cred := &credentials.Credentials{
		AccessKeyId:     v.AccessKeyID,
		SecretAccessKey: v.SecretAccessKey,
		Token:           v.SessionToken,
		Expiration:      v.Expires,
		ProviderName:    v.Source,
	}

	return cred, nil
}

// ConfigProvider returns the AWS SDK aws.Config for this client.
// AWS SDK v1 terminology retained due to laziness.
func (c *samlRoleClient) ConfigProvider() aws.Config {
	return c.session
}

// ClearCache cleans the cache for this client's AWS credential cache.
func (c *samlRoleClient) ClearCache() error {
	return c.roleProvider.ClearCache()
}
