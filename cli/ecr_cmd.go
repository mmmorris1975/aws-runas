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
	"context"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/mmmorris1975/aws-runas/client"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/urfave/cli/v3"
)

var ecrCmd = &cli.Command{
	Name:      "ecr",
	Usage:     "Shortcuts for working with ECR",
	ArgsUsage: "",
	Commands:  []*cli.Command{ecrLoginCmd},
}

func doEcrSetup(ctx context.Context, cmd *cli.Command, expectedArgs int) (string, client.AwsClient, error) {
	profile, cfg, err := resolveConfig(cmd, expectedArgs)
	if err != nil {
		return "", nil, err
	}

	cntx, cancelFunc := context.WithCancel(ctx)
	defer cancelFunc()

	c, err := clientFactory.Get(cntx, cfg)
	if err != nil {
		return "", nil, err
	}

	if cmd.Bool(refreshFlag.Name) {
		refreshCreds(c)
	}

	var creds *credentials.Credentials
	creds, err = c.CredentialsWithContext(cntx)
	if err != nil {
		return "", nil, err
	}

	if cmd.Bool(expFlag.Name) {
		printCredExpiration(creds)
	}

	if cmd.Bool(whoamiFlag.Name) {
		if err = printCredIdentity(sts.NewFromConfig(c.ConfigProvider())); err != nil {
			return "", nil, err
		}
	}

	return profile, c, nil
}
