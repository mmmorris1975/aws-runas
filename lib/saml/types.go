package saml

import (
	"aws-runas/lib/identity"
	"fmt"
	"net/http"
)

// AwsUrn is the well known SAML URL for AWS
const AwsUrn = "urn:amazon:webservices"

// Client specifies the interface for conforming basic SAML clients
type Client interface {
	Authenticate() error
	Saml(spId string) (string, error)
	SetCookieJar(jar http.CookieJar)
	Client() *SamlClient
}

// AwsSamlClient specifies the interface for AWS aware SAML clients.
// In addition to being a basic saml.Client, it is also an identity.Provider so identity information can
// be retrieved from the SAML endpoint.
type AwsSamlClient interface {
	Client
	identity.Provider
	AwsSaml() (string, error)
	GetSessionDuration() (int64, error)
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
