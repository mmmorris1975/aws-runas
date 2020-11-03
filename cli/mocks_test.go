package cli

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go/aws/client"
	awscred "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/awstesting/mock"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
	"strings"
)

type mockAwsClient bool

func (c *mockAwsClient) Identity() (*identity.Identity, error) {
	if *c {
		return nil, errors.New("err")
	}
	return new(identity.Identity), nil
}

func (c *mockAwsClient) Roles() (*identity.Roles, error) {
	if *c {
		return nil, errors.New("err")
	}
	return new(identity.Roles), nil
}

func (c *mockAwsClient) Credentials() (*credentials.Credentials, error) {
	return c.CredentialsWithContext(context.Background())
}

func (c *mockAwsClient) CredentialsWithContext(ctx awscred.Context) (*credentials.Credentials, error) {
	if *c {
		return nil, errors.New("err")
	}
	return new(credentials.Credentials), nil
}

func (c *mockAwsClient) ConfigProvider() client.ConfigProvider {
	return mock.Session
}

func (c *mockAwsClient) ClearCache() error {
	if *c {
		return errors.New("err")
	}
	return nil
}

type mockConfigResolver bool

func (m *mockConfigResolver) Config(profile string) (*config.AwsConfig, error) {
	if *m {
		return nil, errors.New("error")
	}

	if strings.EqualFold(profile, "saml") {
		return &config.AwsConfig{
			Region:       "us-east-1",
			SamlUrl:      "https://mock.local/saml",
			SamlUsername: "mockUser",
			SamlProvider: "mock",
			ProfileName:  profile,
		}, nil
	}

	if strings.EqualFold(profile, "oidc") {
		return &config.AwsConfig{
			Region:                 "us-east-1",
			WebIdentityUrl:         "https://mock.local/oidc",
			WebIdentityUsername:    "mockUser",
			WebIdentityProvider:    "mock",
			WebIdentityClientId:    "mockClient",
			WebIdentityRedirectUri: "app:/callback",
			ProfileName:            profile,
		}, nil
	}

	return &config.AwsConfig{
		Region:      "us-east-1",
		ProfileName: profile,
	}, nil
}

func (m *mockConfigResolver) Credentials(string) (*config.AwsCredentials, error) {
	if *m {
		return nil, errors.New("error")
	}

	return &config.AwsCredentials{
		SamlPassword:        "",
		WebIdentityPassword: "",
	}, nil
}
