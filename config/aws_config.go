package config

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws/arn"
	"net/url"
	"time"
)

// AwsConfig contains many standard AWS SDK configuration variables, and some non-standard configuration variables used
// to perform the various Assume Role operations.  Fields which support ini-style configuration specify the configuration
// key in the "ini" tag.  Fields which support configuration by environment variables specify the environment variable
// name in the "env" tag.
type AwsConfig struct {
	CredentialsDuration    time.Duration `ini:"credentials_duration,omitempty" env:"CREDENTIALS_DURATION"`
	SessionTokenDuration   time.Duration `ini:"session_token_duration,omitempty" env:"SESSION_TOKEN_DURATION"` // only relevant to IAM identities
	DurationSeconds        int64         `ini:"duration_seconds,omitempty" env:"DURATION_SECONDS"`
	ExternalId             string        `ini:"external_id,omitempty" env:"EXTERNAL_ID"` // only relevant to IAM identities
	MfaSerial              string        `ini:"mfa_serial,omitempty" env:"MFA_SERIAL"`   // only relevant to IAM identities
	MfaCode                string        `ini:"-" env:"MFA_CODE"`                        // only env var supported, since this value frequently changes over time
	MfaType                string        `ini:"mfa_type" env:"MFA_TYPE"`                 // only relevant for external IdP clients
	Region                 string        `ini:"region,omitempty" env:"AWS_REGION,AWS_DEFAULT_REGION"`
	RoleArn                string        `ini:"role_arn"`                                                // env var not supported, comes in as command argument
	RoleSessionName        string        `ini:"role_session_name,omitempty" env:"AWS_ROLE_SESSION_NAME"` // don't use? (only use IAM identity info or *_username for value?)
	SrcProfile             string        `ini:"source_profile,omitempty"`                                // env var not supported, only found in config file, and should not be explicitly set
	JumpRoleArn            string        `ini:"jump_role_arn,omitempty" env:"JUMP_ROLE_ARN"`
	SamlUrl                string        `ini:"saml_auth_url,omitempty" env:"SAML_AUTH_URL"`
	SamlUsername           string        `ini:"saml_username,omitempty" env:"SAML_USERNAME"`
	SamlProvider           string        `ini:"saml_provider,omitempty" env:"SAML_PROVIDER"`
	WebIdentityUrl         string        `ini:"web_identity_auth_url,omitempty" env:"WEB_IDENTITY_AUTH_URL"`
	WebIdentityUsername    string        `ini:"web_identity_username,omitempty" env:"WEB_IDENTITY_USERNAME"`
	WebIdentityProvider    string        `ini:"web_identity_provider,omitempty" env:"WEB_IDENTITY_PROVIDER"`
	WebIdentityTokenFile   string        `ini:"web_identity_token_file,omitempty" env:"AWS_WEB_IDENTITY_TOKEN_FILE"`
	WebIdentityClientId    string        `ini:"web_identity_client_id,omitempty" env:"WEB_IDENTITY_CLIENT_ID"`
	WebIdentityRedirectUri string        `ini:"web_identity_redirect_uri,omitempty" env:"WEB_IDENTITY_REDIRECT_URI"`
	FederatedUsername      string        `ini:"federated_username,omitempty" env:"FEDERATED_USERNAME"`
	ProfileName            string        `ini:"-"` // does not participate in Marshal/Unmarshal, explicitly set
	sourceProfile          *AwsConfig
}

// SourceProfile returns a resolved AwsConfig object for the SrcProfile field in the AwsConfig object.
func (c *AwsConfig) SourceProfile() *AwsConfig {
	return c.sourceProfile
}

// SetSourceProfile set the source profile fields for the configuration.
func (c *AwsConfig) SetSourceProfile(p *AwsConfig) {
	c.sourceProfile = p
	c.SrcProfile = p.ProfileName
}

// RoleCredentialDuration normalizes the selection of the Assume Role credential duration.  If the CredentialsDuration
// field has a value greater than 0, it will return that value directly.  Otherwise the value of the DurationSeconds
// field will be converted to a time.Duration type and returned.
func (c *AwsConfig) RoleCredentialDuration() time.Duration {
	if c.CredentialsDuration > 0 {
		return c.CredentialsDuration
	}
	return time.Duration(c.DurationSeconds) * time.Second
}

// RoleARN returns the arn.ARN value for the RoleArn field in the AwsConfig object.
func (c *AwsConfig) RoleARN() (arn.ARN, error) {
	return arn.Parse(c.RoleArn)
}

// JumpRoleARN returns the arn.ARN value for the JumpRoleArn field in the AwsConfig object.
func (c *AwsConfig) JumpRoleARN() (arn.ARN, error) {
	return arn.Parse(c.JumpRoleArn)
}

// SamlURL returns the url.URL value for the SamlUrl field in the AwsConfig object.
func (c *AwsConfig) SamlURL() (*url.URL, error) {
	return c.handleUrl(c.SamlUrl)
}

// WebIdentityURL returns the url.URL value for the WebIdentityUrl field in the AwsConfig object.
func (c *AwsConfig) WebIdentityURL() (*url.URL, error) {
	return c.handleUrl(c.WebIdentityUrl)
}

// MergeIn takes the settings in the provided "config" argument and applies them to the existing AwsConfig object.
// New values are applied only if they are not the field type's zero value, the last (non-zero) value take priority.
//nolint:funlen,gocognit,gocyclo // couldn't make this shorter if we tried
func (c *AwsConfig) MergeIn(config ...*AwsConfig) {
	for _, cfg := range config {
		if cfg.CredentialsDuration > 0 {
			c.CredentialsDuration = cfg.CredentialsDuration
		}

		if cfg.SessionTokenDuration > 0 {
			c.SessionTokenDuration = cfg.SessionTokenDuration
		}

		if cfg.DurationSeconds > 0 {
			c.DurationSeconds = cfg.DurationSeconds
		}

		if len(cfg.ExternalId) > 0 {
			c.ExternalId = cfg.ExternalId
		}

		if len(cfg.MfaSerial) > 0 {
			c.MfaSerial = cfg.MfaSerial
		}

		if len(cfg.MfaCode) > 0 {
			c.MfaCode = cfg.MfaCode
		}

		if len(cfg.MfaType) > 0 {
			c.MfaType = cfg.MfaType
		}

		if len(cfg.Region) > 0 {
			c.Region = cfg.Region
		}

		if len(cfg.RoleArn) > 0 {
			c.RoleArn = cfg.RoleArn
		}

		if len(cfg.RoleSessionName) > 0 {
			c.RoleSessionName = cfg.RoleSessionName
		}

		if len(cfg.SrcProfile) > 0 {
			c.SrcProfile = cfg.SrcProfile
			c.sourceProfile = cfg.sourceProfile
		}

		if len(cfg.JumpRoleArn) > 0 {
			c.JumpRoleArn = cfg.JumpRoleArn
		}

		if len(cfg.SamlUrl) > 0 {
			c.SamlUrl = cfg.SamlUrl
		}

		if len(cfg.SamlUsername) > 0 {
			c.SamlUsername = cfg.SamlUsername
		}

		if len(cfg.SamlProvider) > 0 {
			c.SamlProvider = cfg.SamlProvider
		}

		if len(cfg.WebIdentityUrl) > 0 {
			c.WebIdentityUrl = cfg.WebIdentityUrl
		}

		if len(cfg.WebIdentityUsername) > 0 {
			c.WebIdentityUsername = cfg.WebIdentityUsername
		}

		if len(cfg.WebIdentityProvider) > 0 {
			c.WebIdentityProvider = cfg.WebIdentityProvider
		}

		if len(cfg.WebIdentityTokenFile) > 0 {
			c.WebIdentityTokenFile = cfg.WebIdentityTokenFile
		}

		if len(cfg.WebIdentityClientId) > 0 {
			c.WebIdentityClientId = cfg.WebIdentityClientId
		}

		if len(cfg.WebIdentityRedirectUri) > 0 {
			c.WebIdentityRedirectUri = cfg.WebIdentityRedirectUri
		}

		if len(cfg.FederatedUsername) > 0 {
			c.FederatedUsername = cfg.FederatedUsername
		}
	}
}

// Validate checks that the current configuration settings are sane.
// It performs the following tests:
//  * Check that sourceProfile != nil if SrcProfile is set
//  * Check that only one of SamlUrl or WebIdentityUrl is set
//  * Check that all required Web Identity fields (WebIdentityClientId, WebIdentityRedirectUri)
//    are configured if WebIdentityUrl is set.
func (c *AwsConfig) Validate() error {
	if len(c.SrcProfile) > 0 && c.sourceProfile == nil {
		return errors.New("found source profile name but no source profile data")
	}

	if len(c.SamlUrl) > 0 && len(c.WebIdentityUrl) > 0 {
		return errors.New("can not set SAML provider URL and Web Identity provider URL together")
	}

	if len(c.WebIdentityUrl) > 0 && (len(c.WebIdentityClientId) < 1 || len(c.WebIdentityRedirectUri) < 1) {
		return errors.New("incomplete Web Identity configuration, missing client ID or redirect URI")
	}

	return nil
}

func (c *AwsConfig) handleUrl(u string) (*url.URL, error) {
	if len(u) < 1 {
		return nil, &url.Error{
			Op:  "parse",
			URL: u,
			Err: errors.New("invalid url"),
		}
	}

	return url.Parse(u)
}
