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
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"time"
)

const (
	// AssumeRoleProviderName is the name given to this AWS credential provider.
	AssumeRoleProviderName = "AssumeRoleProvider"
	// AssumeRoleDurationMin is the minimum allowed Assume Role credential duration by the AWS API.
	AssumeRoleDurationMin = 15 * time.Minute
	// AssumeRoleDurationMax is the maximum allowed Assume Role credential duration by the AWS API.
	AssumeRoleDurationMax = 12 * time.Hour
	// AssumeRoleDurationDefault is a sensible default value for Assume Role credential duration.
	AssumeRoleDurationDefault = 1 * time.Hour
)

// AssumeRoleProvider contains the settings to perform the AssumeRole operation in the AWS API.
// An optional Cache provides the ability to cache the credentials in order to limit API calls.
type AssumeRoleProvider struct {
	*baseStsProvider
	ExternalId      string
	RoleArn         string
	RoleSessionName string
}

// NewAssumeRoleProvider configures a default AssumeRoleProvider to allow Assume Role.  The default provider uses
// the specified client.ConfigProvider to create a new sts.STS client and the roleArn argument as the role to assume.
// The credential duration is set to AssumeRoleDefaultDuration, and the ExpiryWindow is set to 10% of the duration value.
func NewAssumeRoleProvider(cfg aws.Config, roleArn string) *AssumeRoleProvider {
	p := &AssumeRoleProvider{
		baseStsProvider: newBaseStsProvider(cfg),
		RoleArn:         roleArn,
	}
	p.Duration = AssumeRoleDurationDefault
	p.ExpiryWindow = -1

	return p
}

// RetrieveWithContext implements the AWS credentials.ProviderWithContext interface to return a set of Assume Role
// credentials, using the provided context argument.  If the provider is configured to use a cache, it will be
// consulted to load the credentials.  If the credentials are expired, the credentials will be refreshed (prompting for
// MFA, if necessary), and stored back in the cache.
func (p *AssumeRoleProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	var err error
	creds := p.CheckCache()

	if creds == nil || creds.Value().Expired() {
		p.Logger.Debugf("Detected expired or unset assume role credentials, refreshing")
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
	v.Source = AssumeRoleProviderName

	p.Logger.Debugf("ASSUME ROLE CREDENTIALS: %+v", v)
	return v, nil
}

func (p AssumeRoleProvider) retrieve(ctx context.Context) (*Credentials, error) {
	in, err := p.getAssumeRoleInput()
	if err != nil {
		return nil, err
	}

	out, err := p.Client.AssumeRole(ctx, in)
	if err != nil {
		return nil, err
	}

	if p.ExpiryWindow < 1 {
		p.ExpiryWindow = p.Duration / 10
	}

	c := FromStsCredentials(out.Credentials)
	return c, nil
}

func (p AssumeRoleProvider) getAssumeRoleInput() (*sts.AssumeRoleInput, error) {
	in := &sts.AssumeRoleInput{
		DurationSeconds: p.ConvertDuration(p.Duration, AssumeRoleDurationMin, AssumeRoleDurationMax, AssumeRoleDurationDefault),
		RoleArn:         aws.String(p.RoleArn),
		RoleSessionName: aws.String(p.RoleSessionName),
	}

	if len(p.SerialNumber) > 0 {
		in.SerialNumber = aws.String(p.SerialNumber)
	}

	if len(p.ExternalId) > 0 {
		in.ExternalId = aws.String(p.ExternalId)
	}

	code, err := p.handleMfa()
	if err != nil {
		return nil, err
	}
	in.TokenCode = code

	return in, nil
}
