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

package config

// AwsCredentials contains the "non-standard" AWS credential information for SAML or Web Identity (OIDC) configurations
// which use this feature.  The data in these fields will be the raw value. Logic to decrypt/unobfuscate the values
// must be done externally. AWS IAM credentials will be resolved and managed using the build-in SDK logic.
type AwsCredentials struct {
	SamlPassword        string `ini:"saml_password,omitempty" env:"SAML_PASSWORD"`
	WebIdentityPassword string `ini:"web_identity_password,omitempty" env:"WEB_PASSWORD"`
}

// MergeIn takes the credential settings in the provided "creds" argument and applies them to the existing
// AwsCredentials object.  New values are applied only if they are not the field type's zero value, the last
// (non-zero) value take priority.
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
