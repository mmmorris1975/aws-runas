package saml

import (
	"aws-runas/lib/identity"
	"fmt"
	"net/http"
)

const (
	// AwsUrn is the well known SAML URL for AWS
	AwsUrn = "urn:amazon:webservices"
	// MfaTypeNone indicates that no MFA should be attempted regardless of the state of other MFA configuration
	MfaTypeNone = "none"
	// MfaTypeAuto indicates that the MFA type to use should be auto detected (as determined by each concrete provider)
	MfaTypeAuto = "auto"
	// MfaTypeCode indicates the use of MFA token/otp codes
	MfaTypeCode = "code"
	// MfaTypePush indicates the use of MFA push notifications
	MfaTypePush = "push"
	// IdentityProviderSaml is the name which names the the provider which resolved the identity
	IdentityProviderSaml = "SAMLIdentityProvider"
)

// AwsClient specifies the interface for AWS aware SAML clients.  Conforming types also implement
// identity.Provider so identity information can be retrieved from the SAML endpoint.
type AwsClient interface {
	identity.Provider
	Authenticate() error
	SetCookieJar(jar http.CookieJar)
	AwsSaml() (string, error)
	GetSessionDuration() (int64, error)
	Client() *baseAwsClient
}

type errAuthFailure struct {
	error
	code int
}

func (e *errAuthFailure) WithCode(code int) *errAuthFailure {
	e.code = code
	return e
}

func (e *errAuthFailure) Error() string {
	return fmt.Sprintf("auth status code %d", e.code)
}

type errMfaFailure struct {
	error
	code int
}

func (e *errMfaFailure) WithCode(code int) *errMfaFailure {
	e.code = code
	return e
}

func (e errMfaFailure) Error() string {
	return fmt.Sprintf("mfa status code %d", e.code)
}

type errMfaNotConfigured struct {
	error
}

func (e errMfaNotConfigured) Error() string {
	return "MFA token is empty, and no token provider configured"
}
