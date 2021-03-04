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

type SamlRoleProvider interface {
	aws.CredentialsProvider
	SamlAssertion(saml *SamlAssertion)
	ClearCache() error
}

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
