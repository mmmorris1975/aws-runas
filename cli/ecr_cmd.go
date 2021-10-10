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
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/mmmorris1975/aws-runas/client"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/urfave/cli/v2"
)

var ecrCmd = &cli.Command{
	Name:        "ecr",
	Usage:       "Shortcuts for working with ECR",
	ArgsUsage:   "",
	Subcommands: []*cli.Command{ecrLoginCmd},
}

func doEcrSetup(ctx *cli.Context, expectedArgs int) (string, client.AwsClient, error) {
	profile, cfg, err := resolveConfig(ctx, expectedArgs)
	if err != nil {
		return "", nil, err
	}

	c, err := clientFactory.Get(cfg)
	if err != nil {
		return "", nil, err
	}

	if ctx.Bool(refreshFlag.Name) {
		refreshCreds(c)
	}

	if ctx.Bool(expFlag.Name) || ctx.Bool(whoamiFlag.Name) {
		var creds *credentials.Credentials
		creds, err = c.Credentials()
		if err != nil {
			return "", nil, err
		}

		if ctx.Bool(expFlag.Name) {
			printCredExpiration(creds)
		}

		if ctx.Bool(whoamiFlag.Name) {
			if err = printCredIdentity(sts.NewFromConfig(c.ConfigProvider())); err != nil {
				return "", nil, err
			}
		}
	}

	return profile, c, nil
}
