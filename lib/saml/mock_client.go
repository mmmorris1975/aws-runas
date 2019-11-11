package saml

import (
	"aws-runas/lib/identity"
	"fmt"
)

type mockSamlClient struct {
	*BaseAwsClient
}

// NewMockSamlClient create a mockSamlClient for testing purposes
func NewMockSamlClient(authUrl string) (*mockSamlClient, error) {
	c := new(mockSamlClient)

	sc, err := newBaseAwsClient(authUrl)
	if err != nil {
		return nil, err
	}
	c.BaseAwsClient = sc

	return c, nil
}

// Authenticate does mock authentication, success only if the Username and Password field
// of the type are both set to the same string ... "good"
func (c *mockSamlClient) Authenticate() error {
	if c.Username == "good" && c.Password == "good" {
		return nil
	}
	return fmt.Errorf("invalid authentication")
}

// AwsSaml calls Saml() with the well-known AWS URN
func (c *mockSamlClient) AwsSaml() (string, error) {
	return "><", nil
}

// GetIdentity returns a mock Identity type with no error
func (c *mockSamlClient) GetIdentity() (*identity.Identity, error) {
	return &identity.Identity{
		IdentityType: "user",
		Provider:     "MockSamlProvider",
		Username:     "mock-user",
	}, nil
}

// Roles returns an empty role list with no error
func (c *mockSamlClient) Roles(user ...string) (identity.Roles, error) {
	return []string{}, nil
}

// GetSessionDuration returns the mock value 12345 with no error
func (c *mockSamlClient) GetSessionDuration() (int64, error) {
	return 12345, nil
}
