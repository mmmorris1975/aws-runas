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
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/mmmorris1975/ssm-session-client/ssmclient"
	"github.com/urfave/cli/v2"
	"os/signal"
)

const ssmShellDesc = `Create an SSM shell session with the specified 'target_spec' using configuration from the
   given 'profile_name'.  The target string can be an EC2 instance ID, a tag key:value string
   which uniquely identifies an EC2 instance, the instance's private IPv4 address, or a DNS
   TXT record whose value is EC2 instance ID.`

var ssmShellCmd = &cli.Command{
	Name:         "shell",
	Aliases:      []string{"sh"},
	Usage:        "Start an SSM shell session",
	ArgsUsage:    "profile_name target_spec",
	Description:  ssmShellDesc,
	BashComplete: bashCompleteProfile,

	Flags: []cli.Flag{ssmUsePluginFlag},

	Action: func(ctx *cli.Context) error {
		target, c, err := doSsmSetup(ctx, 2)
		if err != nil {
			return err
		}

		ec2Id, err := ssmclient.ResolveTarget(target, c.ConfigProvider())
		if err != nil {
			return err
		}

		if ctx.Bool(ssmUsePluginFlag.Name) {
			// install signal handler (native client installs its own handler)
			sigCh := installSignalHandler()
			defer func() {
				signal.Reset()
				close(sigCh)
			}()

			in := &ssm.StartSessionInput{Target: aws.String(ec2Id)}
			return execSsmPlugin(c.ConfigProvider(), in)
		}

		return ssmclient.ShellSession(c.ConfigProvider(), ec2Id)
	},
}
