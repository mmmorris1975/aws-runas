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
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"time"
)

// stsMock provides a mock STS client used for testing.
type stsMock struct {
	stsApi
}

// GetSessionTokenWithContext implements the AWS API for getting Session Token credentials for testing.
func (m *stsMock) GetSessionToken(_ context.Context, in *sts.GetSessionTokenInput, _ ...func(*sts.Options)) (*sts.GetSessionTokenOutput, error) {
	d, err := validateDuration(in.DurationSeconds, 900*time.Second, 36*time.Hour, 12*time.Hour)
	if err != nil {
		return nil, err
	}

	if err = validateMfa(in.SerialNumber, in.TokenCode); err != nil {
		return nil, err
	}

	return &sts.GetSessionTokenOutput{Credentials: buildCredentials(d)}, nil
}

// AssumeRoleWithContext implements the AWS API for getting Assume Role credentials for testing.
func (m *stsMock) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	d, err := validateDuration(in.DurationSeconds, 900*time.Second, 36*time.Hour, 12*time.Hour)
	if err != nil {
		return nil, err
	}

	if err = validateMfa(in.SerialNumber, in.TokenCode); err != nil {
		return nil, err
	}

	if err = validateRoleArn(in.RoleArn); err != nil {
		return nil, err
	}

	if err = validateRoleSessionName(in.RoleSessionName); err != nil {
		return nil, err
	}

	return &sts.AssumeRoleOutput{Credentials: buildCredentials(d)}, nil
}

// AssumeRoleWithSAMLWithContext implements the AWS API for getting role credentials using SAML for testing.
func (m *stsMock) AssumeRoleWithSAML(_ context.Context, in *sts.AssumeRoleWithSAMLInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error) {
	d, err := validateDuration(in.DurationSeconds, 900*time.Second, 36*time.Hour, 12*time.Hour)
	if err != nil {
		return nil, err
	}

	if err = validateRoleArn(in.RoleArn); err != nil {
		return nil, err
	}

	if err = validatePrincipalArn(in.PrincipalArn); err != nil {
		return nil, err
	}

	if err = validateSamlAssertion(in.SAMLAssertion); err != nil {
		return nil, err
	}

	return &sts.AssumeRoleWithSAMLOutput{Credentials: buildCredentials(d)}, nil
}

// AssumeRoleWithWebIdentityWithContext implements the AWS API for getting role credentials using Oauth2/OIDC for testing.
func (m *stsMock) AssumeRoleWithWebIdentity(_ context.Context, in *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	d, err := validateDuration(in.DurationSeconds, 900*time.Second, 36*time.Hour, 12*time.Hour)
	if err != nil {
		return nil, err
	}

	if err = validateRoleArn(in.RoleArn); err != nil {
		return nil, err
	}

	if err = validateRoleSessionName(in.RoleSessionName); err != nil {
		return nil, err
	}

	if err = validateWebIdentityToken(in.WebIdentityToken); err != nil {
		return nil, err
	}

	return &sts.AssumeRoleWithWebIdentityOutput{Credentials: buildCredentials(d)}, nil
}

// if duration != nil (default), must be in acceptable range.
//
//nolint:unparam
func validateDuration(d *int32, min, max, def time.Duration) (time.Duration, error) {
	if d != nil {
		t := time.Duration(*d) * time.Second
		if t < min || t > max {
			return time.Duration(0), errors.New("InvalidParameter")
		}
		return t, nil
	}
	return def, nil
}

func validateMfa(serial, code *string) error {
	if serial != nil && len(*serial) > 0 {
		if code != nil && *code == "123456" {
			return nil
		}
		return errors.New("mfa required")
	}

	// mfa not required
	return nil
}

func validateRoleArn(role *string) error {
	if role != nil && len(*role) > 2 {
		return nil
	}
	return errors.New("invalid role arn")
}

func validateRoleSessionName(name *string) error {
	if name != nil && len(*name) > 2 {
		return nil
	}
	return errors.New("invalid role session name")
}

func validatePrincipalArn(p *string) error {
	if p != nil && len(*p) > 20 {
		return nil
	}
	return errors.New("invalid principal arn")
}

func validateSamlAssertion(a *string) error {
	if a != nil && len(*a) > 4 {
		return nil
	}
	return errors.New("invalid saml assertion")
}

func validateWebIdentityToken(t *string) error {
	if t != nil && len(*t) > 4 {
		return nil
	}
	return errors.New("invalid web identity token")
}

func buildCredentials(d time.Duration) *types.Credentials {
	t := time.Now().Unix()

	return &types.Credentials{
		AccessKeyId:     aws.String(fmt.Sprintf("AKIAM0CK%d", t)),
		Expiration:      aws.Time(time.Now().Add(d)),
		SecretAccessKey: aws.String(fmt.Sprintf("s3cR3TkEy%d", t)),
		SessionToken:    aws.String(fmt.Sprintf("t0k3N%d", t)),
	}
}

type memCredCache struct {
	creds *Credentials
}

func (c *memCredCache) Load() *Credentials {
	if c.creds == nil {
		c.creds = new(Credentials)
	}
	return c.creds
}

func (c *memCredCache) Store(creds *Credentials) error {
	c.creds = creds
	return nil
}

func (c *memCredCache) Clear() error {
	c.creds = nil
	return nil
}
