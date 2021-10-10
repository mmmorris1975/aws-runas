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
	"github.com/mmmorris1975/aws-runas/metadata"
	"github.com/urfave/cli/v2"
	"net"
	"net/url"
	"os"
	"strconv"
)

var ecsCmdDesc = `Start a local web server which mimics the credential retrieval abilities of the ECS container
metadata service.  The main difference being that instead of serving ECS task credentials, this
local server will return role credentials for profiles. This feature may be useful for fetching
credentials from AWS when it is not practical using the traditional 'wrapper' mode of aws-runas.
Omitting the port parameter will cause the service to listen on a random port.

You will need to set the AWS_CONTAINER_CREDENTIALS_FULL_URI environment variable to this
service's address and port so calling programs know the location of the endpoint.`

var ecsCmd = &cli.Command{
	Name:         "ecs",
	Usage:        "Run a mock ECS credential endpoint to provide role credentials",
	ArgsUsage:    "[profile_name]",
	Description:  ecsCmdDesc,
	BashComplete: bashCompleteProfile,

	Flags: []cli.Flag{ecsPortFlag, headlessFlag},

	Action: func(ctx *cli.Context) error {
		profile, _, err := resolveConfig(ctx, 0)
		if err != nil {
			return err
		}

		var addr string
		path := metadata.DefaultEcsCredPath

		if env, ok := os.LookupEnv("AWS_CONTAINER_CREDENTIALS_FULL_URI"); ok {
			log.Debugf("found ECS credential env var")
			var u *url.URL
			if u, err = url.Parse(env); err == nil {
				addr = u.Host

				// only use env var path if it's not "/" (we're reserving that)
				if len(u.Path) > 0 && u.Path != "/" {
					path = u.Path
				}
			}
		}

		if len(addr) < 1 {
			addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(ctx.Uint(ecsPortFlag.Name))))
		}
		log.Debugf("setting ECS credential endpoint HOST=%s, PATH=%s", addr, path)

		in := &metadata.Options{
			Path:        path,
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

var ecsPortFlag = &cli.UintFlag{
	Name:    "port",
	Aliases: []string{"p"},
	Usage:   "The listening port for the ECS credential service",
	Value:   12319, // A (1) W (23) S (19)
}
