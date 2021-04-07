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

package credentials

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestOidcIdentityToken_IsExpired(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		j, _ := json.Marshal(map[string]interface{}{"exp": time.Now().Add(1 * time.Hour).UTC().Unix()})
		tok := OidcIdentityToken(fmt.Sprintf("mock.%s.mock", base64.RawURLEncoding.EncodeToString(j)))
		if tok.IsExpired() {
			t.Error("unexpected expired token")
		}
	})

	t.Run("invalid token format", func(t *testing.T) {
		tok := OidcIdentityToken("mock.payload")
		if !tok.IsExpired() {
			t.Error("handled invalid token")
		}
	})

	t.Run("invalid token payload encoding", func(t *testing.T) {
		tok := OidcIdentityToken("mock.pay|load.mock")
		if !tok.IsExpired() {
			t.Error("handled invalid token")
		}
	})

	t.Run("invalid payload json", func(t *testing.T) {
		// this payload is actually valid base64, but won't be valid json
		tok := OidcIdentityToken("mock.payload.mock")
		if !tok.IsExpired() {
			t.Error("handled invalid token")
		}
	})

	t.Run("invalid payload expiration", func(t *testing.T) {
		j, _ := json.Marshal(map[string]interface{}{"exp": "invalid"})
		tok := OidcIdentityToken(fmt.Sprintf("mock.%s.mock", base64.RawURLEncoding.EncodeToString(j)))
		if !tok.IsExpired() {
			t.Error("handled invalid token")
		}
	})
}

func TestOidcIdentityToken_String(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		tok := OidcIdentityToken("mock")
		if tok.String() != "mock" {
			t.Error("data mismatch")
		}
	})

	t.Run("empty", func(t *testing.T) {
		tok := OidcIdentityToken("")
		if tok.String() != "" {
			t.Error("data mismatch")
		}
	})
}
