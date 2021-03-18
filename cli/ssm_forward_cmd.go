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
	"strconv"
	"strings"
)

const ssmFwdDesc = `Create an SSM port forwarding session with the specified 'target_spec' using configuration
   from the given 'profile_name'.  The 'target_spec' is a colon-separated value of the target
   and remote port number (ex. i-01234567:8080).  The target string can be an EC2 instance ID,
   a tag key:value string which uniquely identifies an EC2 instance, the instance's private
   IPv4 address, or a DNS TXT record whose value is EC2 instance ID.  If the '-p' option is
   given, the port forwarding session will listen on the specified port on the local system,
   otherwise a random port is used.`

var ssmForwardCmd = &cli.Command{
	Name:         "forward",
	Aliases:      []string{"fwd"},
	Usage:        "Start an SSM port forwarding session",
	ArgsUsage:    "profile_name target_spec",
	Description:  ssmFwdDesc,
	BashComplete: bashCompleteProfile,

	Flags: []cli.Flag{ssmFwdPortFlag, ssmUsePluginFlag},

	Action: func(ctx *cli.Context) error {
		target, c, err := doSsmSetup(ctx, 2)
		if err != nil {
			return err
		}

		// "preprocess" target so it's acceptable to checkTarget()
		// port number is expected to be the last element after splitting on ':',
		// all other parts will be passed to checkTarget()
		parts := strings.Split(target, `:`)
		target = strings.Join(parts[:len(parts)-1], `:`)
		rp := parts[len(parts)-1]
		lp := strconv.Itoa(ctx.Int(ssmFwdPortFlag.Name))

		ec2Id, err := ssmclient.ResolveTarget(target, c.ConfigProvider())
		if err != nil {
			return err
		}

		if ctx.Bool(ssmUsePluginFlag.Name) {
			params := map[string][]string{
				"localPortNumber": {lp},
				"portNumber":      {rp},
			}

			in := &ssm.StartSessionInput{
				DocumentName: aws.String("AWS-StartPortForwardingSession"),
				Parameters:   params,
				Target:       aws.String(ec2Id),
			}
			return execSsmPlugin(c.ConfigProvider(), in)
		}

		rpi, _ := strconv.Atoi(rp)
		in := &ssmclient.PortForwardingInput{
			Target:     ec2Id,
			RemotePort: rpi,
			LocalPort:  ctx.Int(ssmFwdPortFlag.Name),
		}
		return ssmclient.PortForwardingSession(c.ConfigProvider(), in)
	},
}

var ssmFwdPortFlag = &cli.UintFlag{
	Name:        "port",
	Aliases:     []string{"p"},
	Usage:       "The local port for the forwarded connection",
	Value:       0,
	DefaultText: "random port",
}
