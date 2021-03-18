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

package metadata

import (
	"net"
	"testing"
)

func Test_DiscoverLoopback(t *testing.T) {
	if _, err := discoverLoopback(); err != nil {
		t.Error(err)
		return
	}
}

func Test_findInterfaceByAddress(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		i, err := findInterfaceByAddress(net.IPv6loopback.String())
		if err != nil {
			// try IPv4 loopback before failing, since the IPv6 address fails in CI
			// never understood why this isn't a language constant like IPv6 loopback
			i, err = findInterfaceByAddress("127.0.0.1")
			if err != nil {
				t.Error(err)
				return
			}
		}

		if i == nil {
			t.Errorf("nil interface")
		}
	})

	t.Run("bad", func(t *testing.T) {
		if _, err := findInterfaceByAddress(net.IPv4allrouter.String()); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func Test_doCommand(t *testing.T) {
	if err := doCommand([]string{"true"}); err != nil {
		t.Error(err)
	}
}
