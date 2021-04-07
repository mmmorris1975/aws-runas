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

// ErrInvalidCredentials is the error returned when a set of invalid AWS credentials is detected.
var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrMfaRequired is the error returned when performing MFA is required to obtain credentials,
// but no source for the MFA information was found.
var ErrMfaRequired = errors.New("MFA required, but no code sent")

// CredentialCacher is the interface details to implement AWS credential caching.
type CredentialCacher interface {
	Load() *Credentials
	Store(cred *Credentials) error
	Clear() error
}

// IdentityTokenCacher defines the methods used for caching Web (OIDC) Identity Tokens.
type IdentityTokenCacher interface {
	Load(url string) *OidcIdentityToken
	Store(url string, token *OidcIdentityToken) error
	Clear() error
}

// SamlRoleProvider defines the methods used for interacting with the AssumeRoleWithSAML call.
type SamlRoleProvider interface {
	aws.CredentialsProvider
	SamlAssertion(saml *SamlAssertion)
	ClearCache() error
}

// WebRoleProvider defines the methods used for interacting with the AssumeRoleWithWebIdentity call.
type WebRoleProvider interface {
	aws.CredentialsProvider
	WebIdentityToken(token *OidcIdentityToken)
	ClearCache() error
}

type stsApi interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	AssumeRoleWithSAML(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error)
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
	GetSessionToken(ctx context.Context, params *sts.GetSessionTokenInput, optFns ...func(*sts.Options)) (*sts.GetSessionTokenOutput, error)
}
