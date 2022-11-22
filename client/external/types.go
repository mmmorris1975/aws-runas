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
	"errors"
	"net/http"

	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
	"github.com/mmmorris1975/aws-runas/shared"
)

const (
	// AwsSamlUrn is the well known SAML URL for AWS.
	AwsSamlUrn = "urn:amazon:webservices"
	// MfaTypeNone indicates that no MFA should be attempted regardless of the state of other MFA configuration.
	MfaTypeNone = "none"
	// MfaTypeAuto indicates that the MFA type to use should be auto detected (as determined by each concrete provider).
	MfaTypeAuto = "auto"
	// MfaTypeCode indicates the use of MFA token/otp codes.
	MfaTypeCode = "code"
	// MfaTypePush indicates the use of MFA push notifications.
	MfaTypePush = "push"

	contentTypeForm = "application/x-www-form-urlencoded"
	contentTypeJson = "application/json"
)

var (
	errMfaNotConfigured   = errors.New("MFA token is empty, and no token provider configured")
	errOauthStateMismatch = errors.New("oauth state token mismatch")
)

// AuthenticationClient is the specification for integration with external identity providers, like Okta,
// which require some sort of user authentication (not attached to AWS) for using the service.
type AuthenticationClient interface {
	Authenticate() error
	AuthenticateWithContext(ctx context.Context) error
	SetCookieJar(jar http.CookieJar)
}

// SamlClient is a type of AuthenticationClient which is capable of returning SAML Assertion documents
// which are used with the AWS AssumeRoleWithSaml API call.
type SamlClient interface {
	identity.Provider
	AuthenticationClient
	SamlAssertion() (*credentials.SamlAssertion, error)
	SamlAssertionWithContext(ctx context.Context) (*credentials.SamlAssertion, error)
}

// WebIdentityClient is a type of AuthenticationClient which is capable of returning an OIDC Identity Token
// which is used with the AWS AssumeRoleWithWebIdentity API call.
//
// There's no notion of roles in the WebIdentity process (it's all managed AWS-side), so the call to the
// identity.Provider Roles() method will return an error, however the Identity() method is implemented.
type WebIdentityClient interface {
	identity.Provider
	AuthenticationClient
	IdentityToken() (*credentials.OidcIdentityToken, error)
	IdentityTokenWithContext(ctx context.Context) (*credentials.OidcIdentityToken, error)
}

// AuthenticationClientConfig holds the properties used to authenticate an identity with an AuthenticationClient.
type AuthenticationClientConfig struct {
	// Username is the username of the principal to authenticate
	Username string
	// Password is the password of the principal to authenticate
	Password string
	// MfaTokenCode is a static, or obtained by means outside of the client, MFA OTP code/token for authentication
	// flows which require the use of OTP code-based (Google Authenticator, TOTP, etc) multi-factor authentication.
	MfaTokenCode string
	// MfaTokenProvider defines a function which the AuthenticationClient can call when an authentication flow
	// requiring MFA OTP codes is detected.
	MfaTokenProvider func() (string, error)
	// MfaType explicitly sets the type of multi-factor authentication to perform with the identity provider.
	// See the MfaType* constants for supported types.
	MfaType string
	// CredentialInputProvider defines a function which the AuthenticationClient can call when performing a
	// username and password style authentication with the identity provider
	CredentialInputProvider func(user, password string) (string, string, error)
	// IdentityProviderName is the name of a supported external identity provider to use with the client's
	// authentication URL.  If left unset, it will attempt to auto-detect the value.
	IdentityProviderName string
	// Logger is the logging interface to use with the client
	Logger shared.Logger
	// FederatedUsername is the username used to authenticate to a federated authentication service, if
	// different from Username
	FederatedUsername string
	AuthBrowser       string
}

// OidcClientConfig is an extension of AuthenticationClientConfig which defines the extra properties needed to
// get OIDC identity tokens from the identity provider.
type OidcClientConfig struct {
	AuthenticationClientConfig
	// ClientId is the OAuth/OIDC Client ID
	ClientId string
	// RedirectUri is the location in the final step of the OIDC token flow which is sent as an HTTP redirect
	// back to our code.  In general, this should be an invalid value (http://localhost, app:/callback, etc)
	// which conforming WebIdentityClient implementations will detect and handle.
	RedirectUri string
	// Scopes are the additional OAuth scopes to request with the identity token.  The 'oidc' scope is always
	// explicitly requested
	Scopes []string
}

type oauthToken struct {
	AccessToken string                         `json:"access_token"`
	ExpiresIn   int                            `json:"expires_in"`
	IdToken     *credentials.OidcIdentityToken `json:"id_token"`
	Scope       string                         `json:"scope"`
	TokenType   string                         `json:"token_type"`
}
