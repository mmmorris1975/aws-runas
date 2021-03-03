package client

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/credentials/helpers"
	"github.com/mmmorris1975/aws-runas/identity"
	"github.com/mmmorris1975/aws-runas/shared"
	"os"
)

var (
	// DefaultOptions is a set of options provided as a convenience for setting common behavior, such as
	// credential caching, logging, and MFA and Credential input prompting.
	DefaultOptions = &Options{
		EnableCache:             true,
		MfaInputProvider:        helpers.NewMfaTokenProvider(os.Stdin).ReadInput,
		CredentialInputProvider: helpers.NewUserPasswordInputProvider(os.Stdin).ReadInput,
		Logger:                  new(shared.DefaultLogger),
		//AwsLogLevel:             aws.LogOff,
		CommandCredentials: new(config.AwsCredentials),
	}
)

// CredentialClient defines the methods for implementations which know how to retrieve AWS credentials using the various
// means of the STS API.
type CredentialClient interface {
	Credentials() (*credentials.Credentials, error)
	CredentialsWithContext(ctx context.Context) (*credentials.Credentials, error)
	ConfigProvider() aws.Config
	ClearCache() error
}

// IdentityClient defines the methods for implementations which retrieve caller identity information for AWS IAM users,
// or identities managed by an external identity source.
type IdentityClient interface {
	Identity() (*identity.Identity, error)
	Roles() (*identity.Roles, error)
}

// AwsClient is a super-interface which combines the functions of the CredentialClient and IdentityClient to provide a
// cohesive solution for obtaining credentials and identity information from various sources.
type AwsClient interface {
	IdentityClient
	CredentialClient
}

// Options provides a way to manage various attributes used by the Client Factory to configure the client selected
// based on the given configuration options.
type Options struct {
	EnableCache             bool
	MfaInputProvider        func() (string, error)
	CredentialInputProvider func(string, string) (string, string, error)
	Logger                  shared.Logger
	//AwsLogLevel             aws.LogLevelType
	CommandCredentials *config.AwsCredentials
}
