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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

type pkceCode struct {
	challenge string
	verifier  string
}

func newPkceCode() (*pkceCode, error) {
	pkce := new(pkceCode)

	buf := make([]byte, 32) // required min length

	// Read() will always fill buf, unless error
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	pkce.verifier = base64.RawURLEncoding.EncodeToString(buf)

	h := sha256.New()
	_, _ = h.Write([]byte(pkce.verifier))
	pkce.challenge = base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return pkce, nil
}

// Challenge returns the PKCE challenge value which is used in the 1st step of the OAuth/OIDC authentication flow.
func (p *pkceCode) Challenge() string {
	return p.challenge
}

// Verifier returns the PKCE verifier value which is used in the final step of the OAuth/OIDC authentication flow.
func (p *pkceCode) Verifier() string {
	return p.verifier
}
