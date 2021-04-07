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

import (
	"reflect"
	"testing"
)

func TestChainLoader_Config(t *testing.T) {
	t.Run("should never error", func(t *testing.T) {
		l := NewChainLoader([]Loader{new(badLoader)})
		c, err := l.Config("")
		if err != nil {
			t.Fatal("chain loader returned an error")
		}

		if !reflect.DeepEqual(AwsConfig{}, *c) {
			t.Error("data mismatch")
		}
	})

	t.Run("full chain", func(t *testing.T) {
		l := NewChainLoader([]Loader{new(samlLoader), new(badLoader), new(simpleLoader)})
		c, _ := l.Config("")

		if c.Region != "mockRegion" || c.SamlUsername != "mockUser" || len(c.SamlUrl) < 1 {
			t.Error("data mismatch")
		}
	})
}

func TestChainLoader_Credentials(t *testing.T) {
	t.Run("should never error", func(t *testing.T) {
		l := NewChainLoader([]Loader{new(badLoader)})
		c, err := l.Credentials("")
		if err != nil {
			t.Fatal("chain loader returned an error")
		}

		if !reflect.DeepEqual(AwsCredentials{}, *c) {
			t.Error("data mismatch")
		}
	})

	t.Run("full chain", func(t *testing.T) {
		l := NewChainLoader([]Loader{new(samlLoader), new(badLoader), new(simpleLoader)})
		c, _ := l.Credentials("")

		if len(c.SamlPassword) < 1 || len(c.WebIdentityPassword) > 0 {
			t.Error("data mismatch")
		}
	})
}
