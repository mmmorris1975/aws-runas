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
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/mmmorris1975/aws-runas/docker"
	"github.com/urfave/cli/v2"
	"strings"
)

const ecrEndpointFmt = `%s.dkr.ecr.%s.amazonaws.com`
const ecrLoginDesc = `Authenticate to ECR endpoints with credentials retrieved for the provided profile.

This command assumes the 'docker' command is accessible from your PATH environment
variable, and performs the 'docker login' action to authenticate with the ECR
endpoint(s).

Zero or more ECR endpoints may be provided as arguments to the command.  If no
endpoint is specified, then the ECR endpoint in the account and region associated
with the provided 'profile_name' is used.  Otherwise, endpoints can be provided
as AWS account numbers only, and the endpoint name will be generated using the
region found for the profile; or a full ECR endpoint name can be specified.`

var ecrLoginCmd = &cli.Command{
	Name:         "login",
	Usage:        "Perform 'docker login' to an ECR endpoint",
	ArgsUsage:    "profile_name [ECR endpoint ...]",
	Description:  ecrLoginDesc,
	BashComplete: bashCompleteProfile,

	Action: func(ctx *cli.Context) error {
		_, c, err := doEcrSetup(ctx, 1)
		if err != nil {
			return err
		}

		var endpoints []string
		if ctx.NArg() < 2 {
			// if no endpoint is explicitly provided, use the endpoint from the profile's account and region
			id, err := sts.NewFromConfig(c.ConfigProvider()).GetCallerIdentity(context.Background(), new(sts.GetCallerIdentityInput))
			if err != nil {
				return err
			}

			endpoints = append(endpoints, fmt.Sprintf(ecrEndpointFmt, *id.Account, c.ConfigProvider().Region))
		} else {
			for _, arg := range ctx.Args().Slice()[1:] {
				// Accept endpoints in the form of the full hostname, or just the account number
				// Account number will be composed with the region from the resolved configuration to form the full endpoint
				if strings.HasSuffix(arg, ".amazonaws.com") {
					endpoints = append(endpoints, arg)
				} else {
					endpoints = append(endpoints, fmt.Sprintf(ecrEndpointFmt, arg, c.ConfigProvider().Region))
				}
			}
		}

		ecr := docker.NewEcrLoginProvider(c.ConfigProvider()).WithLogger(log)
		return ecr.Login(endpoints...)
	},
}
