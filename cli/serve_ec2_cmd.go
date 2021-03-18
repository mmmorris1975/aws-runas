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
	"fmt"
	"github.com/mmmorris1975/aws-runas/metadata"
	"github.com/urfave/cli/v2"
	"net/url"
	"os"
)

var ec2CmdDesc = `Start a local web server which mimics the credential retrieval abilities of the EC2 instance
   metadata service (IMDS). The main difference being that instead of serving EC2 instance profile
   credentials, this local server will return role credentials for profiles. This feature may be
   useful for fetching credentials from AWS when it is not practical using the traditional 'wrapper'
   mode of aws-runas.  Omitting the port parameter will cause the service to listen on the default
   IMDS address and port.  Using a port number of 0 will have the service listen on a random port.

   If you are not using the default IMDS address and port, you will want to set the
   AWS_EC2_METADATA_SERVICE_ENDPOINT environment variable to this service's address and port so
   calling programs know the location of the endpoint.`

var ec2Cmd = &cli.Command{
	Name:         "ec2",
	Usage:        "Run a mock EC2 metadata (IMDS) service to provide role credentials",
	ArgsUsage:    "[profile_name]",
	Description:  ec2CmdDesc,
	BashComplete: bashCompleteProfile,

	Flags: []cli.Flag{ec2PortFlag, headlessFlag},

	Action: func(ctx *cli.Context) error {
		profile, _, err := resolveConfig(ctx, 0)
		if err != nil {
			return err
		}

		var addr string

		// env var must specify the protocol, so we should parse as a URL
		if env, ok := os.LookupEnv("AWS_EC2_METADATA_SERVICE_ENDPOINT"); ok {
			log.Debugf("found EC2 IMDS env var")
			var u *url.URL
			if u, err = url.Parse(env); err == nil {
				addr = u.Host
			}
		}

		if len(addr) < 1 {
			port := ctx.Int(ec2PortFlag.Name)
			if port < 0 {
				addr = fmt.Sprintf("%s:80", metadata.DefaultEc2ImdsAddr)
			} else {
				addr = fmt.Sprintf("127.0.0.1:%d", port)
			}
		}
		log.Debugf("setting EC2 IMDS endpoint host to: %s", addr)

		in := &metadata.Options{
			Profile:     profile,
			Logger:      log,
			AwsLogLevel: opts.AwsLogLevel,
			Headless:    ctx.Bool(headlessFlag.Name),
		}

		mcs, err := metadata.NewMetadataCredentialService(addr, in)
		if err != nil {
			return err
		}
		return mcs.Run()
	},
}

var ec2PortFlag = &cli.IntFlag{
	Name:        "port",
	Aliases:     []string{"p"},
	Usage:       "Custom port for the EC2 credential service",
	Value:       -1, // < 0 = IMDS default (169.254.169.254:80), 0 = localhost:random_port, > 0 = localhost:specified_port
	DefaultText: "IMDS default",
}
