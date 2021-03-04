package client

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
	"github.com/mmmorris1975/aws-runas/shared"
)

type baseIamClient struct {
	creds   *aws.CredentialsCache
	ident   identity.Provider
	session aws.Config
}

func newBaseIamClient(cfg aws.Config, logger shared.Logger) *baseIamClient {
	return &baseIamClient{ident: identity.NewAwsIdentityProvider(cfg).WithLogger(logger), session: cfg}
}

// Identity is the implementation of the IdentityClient interface for retrieving identity information for IAM users.
func (c *baseIamClient) Identity() (*identity.Identity, error) {
	return c.ident.Identity()
}

// Roles is the implementation of the IdentityClient interface for retrieving IAM role information for IAM users.
func (c *baseIamClient) Roles() (*identity.Roles, error) {
	return c.ident.Roles()
}

// Credentials is the implementation of the CredentialClient interface, and calls CredentialsWithContext with a
// background context.
func (c *baseIamClient) Credentials() (*credentials.Credentials, error) {
	return c.CredentialsWithContext(context.Background())
}

// CredentialsWithContext is the implementation of the CredentialClient interface for retrieving temporary AWS
// credentials.
func (c *baseIamClient) CredentialsWithContext(ctx context.Context) (*credentials.Credentials, error) {
	if c.creds != nil {
		v, err := c.creds.Retrieve(ctx)
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
	return nil, errors.New("credential provider is not set")
}

// ConfigProvider returns the AWS SDK aws.Config for this client.
// AWS SDK v1 terminology retained due to laziness.
func (c *baseIamClient) ConfigProvider() aws.Config {
	// Don't simply return c.session, since that will only get the credentials which underpin the actual
	// credentials we're looking for. Return a new session object with the credentials set to our internal
	// AWS Credentials resource so the returned client.ConfigProvider will fetch the correct credentials.
	cfg := c.session.Copy()
	cfg.Credentials = c.creds
	return cfg
}
