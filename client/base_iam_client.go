package client

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	awscred "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
	"github.com/mmmorris1975/aws-runas/shared"
)

type baseIamClient struct {
	creds   *awscred.Credentials
	ident   identity.Provider
	session client.ConfigProvider
}

func newBaseIamClient(cfg client.ConfigProvider, logger shared.Logger) *baseIamClient {
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
	return c.CredentialsWithContext(aws.BackgroundContext())
}

// CredentialsWithContext is the implementation of the CredentialClient interface for retrieving temporary AWS
// credentials.
func (c *baseIamClient) CredentialsWithContext(ctx awscred.Context) (*credentials.Credentials, error) {
	if c.creds != nil {
		v, err := c.creds.GetWithContext(ctx)
		if err != nil {
			return nil, err
		}

		t, err := c.creds.ExpiresAt()
		if err != nil {
			return nil, err
		}

		cred := &credentials.Credentials{
			AccessKeyId:     v.AccessKeyID,
			SecretAccessKey: v.SecretAccessKey,
			Token:           v.SessionToken,
			Expiration:      t,
			ProviderName:    v.ProviderName,
		}
		return cred, nil
	}
	return nil, errors.New("credential provider is not set")
}

func (c *baseIamClient) ConfigProvider() client.ConfigProvider {
	// Don't simply return c.session, since that will only get the credentials which underpin the actual
	// credentials we're looking for. Return a new session object with the credentials set to our internal
	// AWS Credentials resource so the returned client.ConfigProvider will fetch the correct credentials.
	cfg := c.session.ClientConfig(sts.ServiceName, new(aws.Config).WithCredentials(c.creds)).Config
	return session.Must(session.NewSession(cfg))
}
