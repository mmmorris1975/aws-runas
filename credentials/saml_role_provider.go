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

package credentials

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	// SamlRoleProviderName is the name given to this AWS credential provider.
	SamlRoleProviderName = "samlRoleProvider"
)

// samlRoleProvider contains the settings to perform the AssumeRoleWithSAML operation in the AWS API.
// An optional Cache provides the ability to cache the credentials in order to limit API calls.
type samlRoleProvider struct {
	*AssumeRoleProvider
	samlAssertion *SamlAssertion
}

// NewSamlRoleProvider configures a default samlRoleProvider to allow Assume Role using SAML.  The default provider uses
// the specified client.ConfigProvider to create a new sts.STS client, the roleArn argument as the role to assume, and
// saml is the base64 encoded SAML assertion which was returned after performing the necessary operations against the
// identity provider. The credential duration is set to AssumeRoleDefaultDuration, and the ExpiryWindow is set to 10% of
// the duration value.
func NewSamlRoleProvider(cfg aws.Config, roleArn string, saml *SamlAssertion) *samlRoleProvider {
	return &samlRoleProvider{
		AssumeRoleProvider: NewAssumeRoleProvider(cfg, roleArn),
		samlAssertion:      saml,
	}
}

// SamlAssertion is the implementation of the SamlRoleProvider interface for setting the SAML assertion used for the
// Assume Role with SAML operation.
func (p *samlRoleProvider) SamlAssertion(saml *SamlAssertion) {
	p.samlAssertion = saml
}

// RetrieveWithContext implements the AWS credentials.ProviderWithContext interface to return a set of Assume Role with
// SAML credentials, using the provided context argument.  If the provider is configured to use a cache, it will be
// consulted to load the credentials.  If the credentials are expired, the credentials will be refreshed, and stored back
// in the cache.
func (p *samlRoleProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	var err error
	creds := p.CheckCache()

	if creds == nil || creds.Value().Expired() {
		p.Logger.Debugf("Detected expired or unset saml role credentials, refreshing")
		creds, err = p.retrieve(ctx)
		if err != nil {
			return aws.Credentials{}, err
		}

		if p.Cache != nil {
			if err = p.Cache.Store(creds); err != nil {
				p.Logger.Debugf("error caching credentials: %v", err)
			}
		}
	}

	// afaik, this can never happen
	// if creds == nil {
	//	// something's wacky, expire existing provider creds, and retry
	//	p.SetExpiration(time.Unix(0, 0), 0)
	//	return p.Retrieve()
	// }

	v := creds.Value()
	v.Source = SamlRoleProviderName

	p.Logger.Debugf("SAML ROLE CREDENTIALS: %+v", v)
	return v, nil
}

func (p *samlRoleProvider) retrieve(ctx context.Context) (*Credentials, error) {
	in, err := p.getAssumeRoleWithSamlInput()
	if err != nil {
		return nil, err
	}

	out, err := p.Client.AssumeRoleWithSAML(ctx, in)
	if err != nil {
		return nil, err
	}

	if p.ExpiryWindow < 1 {
		p.ExpiryWindow = p.Duration / 10
	}

	c := FromStsCredentials(out.Credentials)
	return c, nil
}

func (p *samlRoleProvider) getAssumeRoleWithSamlInput() (*sts.AssumeRoleWithSAMLInput, error) {
	if p.samlAssertion == nil || len(*p.samlAssertion) < 20 {
		return nil, errors.New("invalid SAML Assertion detected, check your local SAML and identity provider configuration")
	}

	in := &sts.AssumeRoleWithSAMLInput{
		DurationSeconds: p.ConvertDuration(p.Duration, AssumeRoleDurationMin, AssumeRoleDurationMax, AssumeRoleDurationDefault),
		RoleArn:         aws.String(p.RoleArn),
		SAMLAssertion:   aws.String(p.samlAssertion.String()),
	}

	prin, err := p.samlAssertion.RoleDetails()
	if err != nil {
		return nil, err
	}
	in.PrincipalArn = aws.String(prin.RolePrincipal(p.RoleArn))

	return in, nil
}

func (p *samlRoleProvider) ClearCache() error {
	if p.Cache != nil {
		p.Logger.Debugf("clearing cached saml role credentials")
		return p.Cache.Clear()
	}
	return nil
}
