/*
 * Copyright (c) 2022 Michael Morris. All Rights Reserved.
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

package cli

import (
	"testing"
)

func Test_parseTargetSpec(t *testing.T) {
	t.Run("user@instance:port", func(t *testing.T) {
		user, host, port := parseTargetSpec("user@instance:2222")
		if user != "user" || host != "instance" || port != "2222" {
			t.Error("bad user, host, or port returned")
		}
	})

	t.Run("user@tag:port", func(t *testing.T) {
		user, host, port := parseTargetSpec("user@my_key:value:2222")
		if user != "user" || host != "my_key:value" || port != "2222" {
			t.Error("bad user, host, or port returned")
		}
	})

	t.Run("user@instance", func(t *testing.T) {
		user, host, port := parseTargetSpec("user@instance")
		if user != "user" || host != "instance" || port != "22" {
			t.Error("bad user, host, or port returned")
		}
	})

	t.Run("user@tag", func(t *testing.T) {
		user, host, port := parseTargetSpec("user@my_key:value")
		if user != "user" || host != "my_key:value" || port != "22" {
			t.Error("bad user, host, or port returned")
		}
	})

	t.Run("instance:port", func(t *testing.T) {
		user, host, port := parseTargetSpec("instance:2222")
		if user != "ec2-user" || host != "instance" || port != "2222" {
			t.Error("bad user, host, or port returned")
		}
	})

	t.Run("tag:port", func(t *testing.T) {
		user, host, port := parseTargetSpec("my_key:value:2222")
		if user != "ec2-user" || host != "my_key:value" || port != "2222" {
			t.Error("bad user, host, or port returned")
		}
	})
}

func Test_getPubKey(t *testing.T) {
	t.Skip("not testable, can't specify custom config file location")
}
