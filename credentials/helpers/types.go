package helpers

// CredentialInputProvider specifies the interface for gathering username and password credentials to use
// with SAML and Oauth/OIDC clients when interacting with the identity provider.
type CredentialInputProvider interface {
	ReadInput(user, password string) (string, string, error)
}

// MfaInputProvider specifies the interfaces for getting MFA values (typically OTP codes) to use with
// credential providers which support MFA.  The value returned from the ReadInput() method is compatible
// with the expectations of the AWS SDK TokenProvider field for the API input types.
type MfaInputProvider interface {
	ReadInput() (string, error)
}
