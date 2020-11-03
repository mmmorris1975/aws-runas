package config

// AwsCredentials contains the "non-standard" AWS credential information for SAML or Web Identity (OIDC) configurations
// which use this feature.  The data in these fields will be the raw value. Logic to decrypt/unobfuscate the values
// must be done externally. AWS IAM credentials will be resolved and managed using the build-in SDK logic.
type AwsCredentials struct {
	SamlPassword        string `ini:"saml_password" env:"SAML_PASSWORD"`
	WebIdentityPassword string `ini:"web_identity_password" env:"WEB_IDENTITY_PASSWORD"`
}

// MergeIn takes the credential settings in the provided "creds" argument and applies them to the existing AwsCredentials
// object.  New values are applied only if they are not the field type's zero value, the last (non-zero) value take priority.
func (c *AwsCredentials) MergeIn(creds ...*AwsCredentials) {
	for _, cr := range creds {
		if len(cr.SamlPassword) > 0 {
			c.SamlPassword = cr.SamlPassword
		}

		if len(cr.WebIdentityPassword) > 0 {
			c.WebIdentityPassword = cr.WebIdentityPassword
		}
	}
}
