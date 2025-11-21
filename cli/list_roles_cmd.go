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
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/urfave/cli/v2"
)

var rolesCmd = &cli.Command{
	Name:      "roles",
	Usage:     rolesFlag.Usage,
	ArgsUsage: "[profile_name]",

	BashComplete: bashCompleteProfile,

	Action: func(ctx *cli.Context) error {
		_, cfg, err := resolveConfig(ctx, 1)
		if err != nil {
			return err
		}

		if arn.IsARN(cfg.ProfileName) {
			return errors.New("profile looks like an ARN, check command parameters and environment variables")
		}

		if len(cfg.WebIdentityUrl) > 0 {
			return errors.New("detected Web Identity profile, only IAM and SAML profiles support role enumeration")
		}

		c, err := clientFactory.Get(cfg)
		if err != nil {
			return err
		}

		roles, err := c.Roles()
		if err != nil {
			return err
		}

		// Moved identity call after roles so that username is populated from SAML assertion if available
		id, err := c.Identity()
		if err != nil {
			return err
		}

		sort.Strings(*roles)

		fmt.Printf("Available role ARNs for %s\n", id.Username)
		for _, r := range *roles {
			// filter out wildcards roles, since they can't be used in config files
			if strings.Contains(r, "*") {
				continue
			}
			fmt.Println("  " + r)
		}

		return nil
	},
}
