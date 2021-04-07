/*
 * Copyright (c) 2021 Michael Morris. All Rights Reserved.
 *
 * Licensed under the MIT license (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * https://github.com/mmmorris1975/aws-runas/blob/master/LICENSE
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under the License.
 */

package client

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
	"time"
)

/*
 */
type mockCredProvider struct {
	credentials.AssumeRoleProvider
	sendError bool
}

func (m *mockCredProvider) Retrieve(context.Context) (aws.Credentials, error) {
	if m.sendError {
		return aws.Credentials{}, errors.New("error: Retrieve()")
	}

	return aws.Credentials{
		AccessKeyID:     "mockAK",
		SecretAccessKey: "mockSK",
		SessionToken:    "mockST",
		Source:          "mockProvider",
	}, nil
}

func (m *mockCredProvider) ExpiresAt() time.Time {
	return time.Now().Add(1 * time.Hour).UTC()
}

func (m *mockCredProvider) IsExpired() bool {
	return false
}

/*
 */
type mockIdent struct {
	sendError bool
}

func (m *mockIdent) Roles(...string) (*identity.Roles, error) {
	if m.sendError {
		return nil, errors.New("error: Roles()")
	}

	roles := identity.Roles([]string{"role1", "role2"})
	return &roles, nil
}

func (m *mockIdent) Identity() (*identity.Identity, error) {
	if m.sendError {
		return nil, errors.New("error: Identity()")
	}

	return &identity.Identity{
		IdentityType: "user",
		Provider:     "MockIdentityProvider",
		Username:     "mockUser",
	}, nil
}

/*
 */
type mockResolver bool

func (m *mockResolver) Config(profile string) (*config.AwsConfig, error) {
	cfg := new(config.AwsConfig)
	// explicitly set RoleSessionName to avoid call to AWS for IAM clients, which will fail, no harm for other clients
	cfg.RoleSessionName = "mockName"

	switch profile {
	case "SamlBad":
		cfg.SamlProvider = "mock"
		cfg.SamlUrl = "ftp://example.org/"
	case "SamlJump":
		cfg.SamlProvider = "mock"
		cfg.SamlUrl = "http://localhost/saml"
		cfg.RoleArn = "the Role"
		cfg.JumpRoleArn = "jump Role"
	case "Saml":
		cfg.SamlProvider = "mock"
		cfg.SamlUrl = "http://localhost/saml"
		cfg.RoleArn = "the Role"
	case "WebBad":
		cfg.WebIdentityProvider = "mock"
		cfg.WebIdentityUrl = "ftp://example.org/"
	case "WebJump":
		cfg.WebIdentityProvider = "mock"
		cfg.WebIdentityUrl = "http://localhost/auth"
		cfg.WebIdentityClientId = "mockClient"
		cfg.WebIdentityRedirectUri = "app:/callback"
		cfg.RoleArn = "the Role"
		cfg.JumpRoleArn = "jump Role"
	case "Web":
		cfg.WebIdentityProvider = "mock"
		cfg.WebIdentityUrl = "http://localhost/auth"
		cfg.WebIdentityClientId = "mockClient"
		cfg.WebIdentityRedirectUri = "app:/callback"
		cfg.RoleArn = "the Role"
	case "IamRoleSession":
		cfg.RoleArn = "the Role"
	case "IamRole":
		cfg.RoleArn = "the Role"
		cfg.CredentialsDuration = 6 * time.Hour
	case "":
		return nil, errors.New("error condition")
	}

	return cfg, nil
}

func (m *mockResolver) Credentials(string) (*config.AwsCredentials, error) {
	if *m {
		return nil, errors.New("error condition")
	}
	return new(config.AwsCredentials), nil
}

/*
 */
type mockWebRoleProvider bool

func (p *mockWebRoleProvider) ExpiresAt() time.Time {
	if *p {
		return time.Now().Add(-1 * time.Minute)
	}
	return time.Now().Add(1 * time.Hour)
}

func (p *mockWebRoleProvider) IsExpired() bool {
	return p.ExpiresAt().Before(time.Now())
}

func (p *mockWebRoleProvider) Retrieve(context.Context) (aws.Credentials, error) {
	if *p {
		return aws.Credentials{}, errors.New("failed")
	}

	return aws.Credentials{
		AccessKeyID:     "mockAK",
		SecretAccessKey: "mockSK",
		SessionToken:    "mockToken",
		Source:          "mockWebRoleProvider",
	}, nil
}

func (p *mockWebRoleProvider) WebIdentityToken(*credentials.OidcIdentityToken) {
	// return
}

func (p *mockWebRoleProvider) ClearCache() error {
	return nil
}

/*
 */
type mockSamlRoleProvider bool

func (p *mockSamlRoleProvider) ExpiresAt() time.Time {
	if *p {
		return time.Now().Add(-1 * time.Minute)
	}
	return time.Now().Add(1 * time.Hour)
}

func (p *mockSamlRoleProvider) IsExpired() bool {
	return p.ExpiresAt().Before(time.Now())
}

func (p *mockSamlRoleProvider) Retrieve(context.Context) (aws.Credentials, error) {
	if *p {
		return aws.Credentials{}, errors.New("failed")
	}

	return aws.Credentials{
		AccessKeyID:     "mockAK",
		SecretAccessKey: "mockSK",
		SessionToken:    "mockToken",
		Source:          "mockSamlRoleProvider",
	}, nil
}

func (p *mockSamlRoleProvider) SamlAssertion(*credentials.SamlAssertion) {
	// return
}

func (p *mockSamlRoleProvider) ClearCache() error {
	return nil
}

type memCredCache struct {
	creds *credentials.Credentials
}

func (c *memCredCache) Load() *credentials.Credentials {
	if c.creds == nil {
		c.creds = new(credentials.Credentials)
	}
	return c.creds
}

func (c *memCredCache) Store(creds *credentials.Credentials) error {
	c.creds = creds
	return nil
}

func (c *memCredCache) Clear() error {
	c.creds = nil
	return nil
}
