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
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestUserPasswordInputProvider_ReadInput(t *testing.T) {
	username := "mockUser"
	password := "mockPassword"

	t.Run("creds provided", func(t *testing.T) {
		user, pass, err := NewUserPasswordInputProvider(nil).ReadInput(username, password)
		if err != nil {
			t.Error(err)
			return
		}

		if user != username || pass != password {
			t.Error("data mismatch")
		}
	})

	t.Run("no creds", func(t *testing.T) {
		in := strings.NewReader(fmt.Sprintf("%s\n%s", username, password))
		user, pass, err := NewUserPasswordInputProvider(in).ReadInput("", "")
		if err != nil {
			t.Error(err)
			return
		}

		if user != username || pass != password {
			t.Error("data mismatch")
		}
	})

	t.Run("user only", func(t *testing.T) {
		in := strings.NewReader(password)
		user, pass, err := NewUserPasswordInputProvider(in).ReadInput(username, "")
		if err != nil {
			t.Error(err)
			return
		}

		if user != username || pass != password {
			t.Error("data mismatch")
		}
	})

	t.Run("password only", func(t *testing.T) {
		in := strings.NewReader(username)
		user, pass, err := NewUserPasswordInputProvider(in).ReadInput("", password)
		if err != nil {
			t.Error(err)
			return
		}

		if user != username || pass != password {
			t.Error("data mismatch")
		}
	})

	t.Run("file input", func(t *testing.T) {
		// This really isn't testable, at least for reading input using terminal.ReadPassword()
		// which requires a legit terminal ... that isn't available while testing.  Just try to
		// bump up those coverage numbers.
		_, _, err := NewUserPasswordInputProvider(os.Stdin).ReadInput(username, "")
		if err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("no user with error", func(t *testing.T) {
		_, _, err := NewUserPasswordInputProvider(new(errReader)).ReadInput("", "pw")
		if err == nil {
			t.Error("did not receive expected error")
		}

		t.Logf("")
	})

	t.Run("no user with error", func(t *testing.T) {
		_, _, err := NewUserPasswordInputProvider(new(errReader)).ReadInput("u", "")
		if err == nil {
			t.Error("did not receive expected error")
		}

		t.Logf("")
	})
}
