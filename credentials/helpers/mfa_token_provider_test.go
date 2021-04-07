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

import (
	"strings"
	"testing"
)

func TestMfaTokenProvider_ReadInput(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		str := "mock_mfa"

		mfa, err := NewMfaTokenProvider(strings.NewReader(str)).ReadInput()
		if err != nil {
			t.Error(err)
			return
		}

		// Not sure why, but not having this causes the test harness to mark the test as not successful
		// (not failed, but some weird intermediate state), unless the test was run under a debugger
		t.Log("")

		if mfa != str {
			t.Error("data mismatch")
		}
	})

	t.Run("bad", func(t *testing.T) {
		if _, err := NewMfaTokenProvider(new(errReader)).ReadInput(); err == nil {
			t.Error("did not receive expected error")
		}

		// Not sure why, but not having this causes the test harness to mark the test as not successful
		// (not failed, but some weird intermediate state), unless the test was run under a debugger
		t.Log("")
	})
}
