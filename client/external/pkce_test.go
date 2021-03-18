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
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestPkceCode(t *testing.T) {
	pkce, err := newPkceCode()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("challenge", func(t *testing.T) {
		if pkce.challenge != pkce.Challenge() {
			t.Error("challenge mismatch")
		}

		if strings.HasSuffix(pkce.Challenge(), `=`) {
			t.Error("challenge must be Raw URL encoded (no padding)")
		}
	})

	t.Run("verifier", func(t *testing.T) {
		if pkce.verifier != pkce.Verifier() {
			t.Error("verifier mismatch")
		}

		if len(pkce.Verifier()) < 43 {
			t.Error("verifier must be at least 43 characters")
		}
	})

	t.Run("hash", func(t *testing.T) {
		h := sha256.New()
		_, _ = h.Write([]byte(pkce.Verifier()))

		if pkce.Challenge() != base64.RawURLEncoding.EncodeToString(h.Sum(nil)) {
			t.Error("invalid challenge hash")
		}
	})
}

func BenchmarkPkceCode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = newPkceCode()
	}
}
