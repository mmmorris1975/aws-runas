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

package cli

import (
	"flag"
	"github.com/urfave/cli/v2"
	"os"
	"testing"
)

func TestListRolesCmd_Action(t *testing.T) {
	configResolver = new(mockConfigResolver)
	ctx := cli.NewContext(App, new(flag.FlagSet), nil)

	t.Run("saml", func(t *testing.T) {
		_ = os.Setenv("AWS_PROFILE", "saml")
		defer os.Unsetenv("AWS_PROFILE")

		if err := rolesCmd.Run(ctx); err != nil {
			t.Error(err)
		}
	})

	t.Run("oidc", func(t *testing.T) {
		_ = os.Setenv("AWS_PROFILE", "oidc")
		defer os.Unsetenv("AWS_PROFILE")

		if err := rolesCmd.Run(ctx); err == nil {
			t.Error("did not receive expected error")
		}
	})
}
