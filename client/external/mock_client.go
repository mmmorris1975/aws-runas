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

package external

import (
	"context"
	"encoding/base64"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
)

type mockClient struct {
	*baseClient
}

// NewMockClient provides a Saml and Web client suitable for testing code outside of this package.
// It returns zero-value objects, and never errors.
func NewMockClient(url string) (*mockClient, error) {
	bc, err := newBaseClient(url)
	if err != nil {
		return nil, err
	}

	return &mockClient{bc}, nil
}

// Identity returns an empty identity.
func (m *mockClient) Identity() (*identity.Identity, error) {
	return new(identity.Identity), nil
}

// Authenticate calls AuthenticateWithContext using a background context.
func (m *mockClient) Authenticate() error {
	return m.AuthenticateWithContext(context.Background())
}

// AuthenticateWithContext always succeeds.
func (m *mockClient) AuthenticateWithContext(context.Context) error {
	return nil
}

// Roles retrieves the available roles for the user.  Attempting to call this method
// against an Oauth/OIDC client will return an error.
func (m *mockClient) Roles(...string) (*identity.Roles, error) {
	if m.saml == nil || len(*m.saml) < 1 {
		var err error
		m.saml, err = m.SamlAssertion()
		if err != nil {
			return nil, err
		}
	}

	return m.roles()
}

// IdentityToken calls IdentityTokenWithContext using a background context.
func (m *mockClient) IdentityToken() (*credentials.OidcIdentityToken, error) {
	return m.IdentityTokenWithContext(context.Background())
}

// IdentityTokenWithContext returns an empty OidcIdentityToken type.
func (m *mockClient) IdentityTokenWithContext(context.Context) (*credentials.OidcIdentityToken, error) {
	_ = m.Authenticate()
	return new(credentials.OidcIdentityToken), nil
}

// SamlAssertion calls SamlAssertionWithContext using a background context.
func (m *mockClient) SamlAssertion() (*credentials.SamlAssertion, error) {
	return m.SamlAssertionWithContext(context.Background())
}

// SamlAssertionWithContext returns a "valid enough" SamlAssertion type.
func (m *mockClient) SamlAssertionWithContext(context.Context) (*credentials.SamlAssertion, error) {
	if m.baseClient == nil {
		m.baseClient = new(baseClient)
	}

	_ = m.Authenticate()
	v := base64.StdEncoding.EncodeToString([]byte(">arn:aws:iam::123:role/role1,arn:aws:iam::123:saml-provider/mock<"))
	saml := credentials.SamlAssertion(v)
	m.saml = &saml
	return m.saml, nil
}
