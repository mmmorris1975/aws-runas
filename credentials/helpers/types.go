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
