package credentials

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

// ErrInvalidCredentials is the error returned when a set of invalid AWS credentials is detected
var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrMfaRequired is the error returned when performing MFA is required to obtain credentials,
// but no source for the MFA information was found.
var ErrMfaRequired = errors.New("MFA required, but no code sent")

// CredentialCacher is the interface details to implement AWS credential caching
type CredentialCacher interface {
	Load() *Credentials
	Store(cred *Credentials) error
	Clear() error
}

// IdentityTokenCacher defines the methods used for caching Web (OIDC) Identity Tokens
type IdentityTokenCacher interface {
	Load(url string) *OidcIdentityToken
	Store(url string, token *OidcIdentityToken) error
	Clear() error
}

type SamlRoleProvider interface {
	credentials.Expirer
	credentials.ProviderWithContext
	SamlAssertion(saml *SamlAssertion)
	ClearCache() error
}

type WebRoleProvider interface {
	credentials.Expirer
	credentials.ProviderWithContext
	WebIdentityToken(token *OidcIdentityToken)
	ClearCache() error
}
