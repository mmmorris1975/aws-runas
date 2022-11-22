/*
 * Copyright (c) 2022 Craig McNiel. All Rights Reserved.
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

import "testing"

func TestNewBrowserClient(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c, err := NewBrowserClient("http://localhost")
		if err != nil {
			t.Fatal("err")
		}

		if c == nil {
			t.Fatal("nil client")
		}
	})

	t.Run("bad url", func(t *testing.T) {
		if _, err := NewBrowserClient("ftp://example.org"); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestBrowserClient_Authenticate(t *testing.T) {
	if err := new(browserClient).Authenticate(); err != nil {
		t.Error(err)
	}
}

func TestBrowserClient_Identity(t *testing.T) {
	if _, err := new(browserClient).Identity(); err != nil {
		t.Error(err)
	}
}

func TestBrowserClient_IdentityToken(t *testing.T) {
	if _, err := new(browserClient).IdentityToken(); err != nil {
		t.Error(err)
	}
}

func TestBrowserClient_SamlAssertion(t *testing.T) {
	if _, err := new(browserClient).SamlAssertion(); err != nil {
		t.Error(err)
	}
}
