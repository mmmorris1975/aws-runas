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
	"encoding/json"
	"os"
	"os/exec"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/mmmorris1975/aws-runas/client"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/urfave/cli/v3"
)

var ssmCmd = &cli.Command{
	Name:      "ssm",
	Usage:     "Helpful shortcuts for working with SSM sessions",
	ArgsUsage: " ", // this hides the default '[arguments...]' help text output, since we don't use command args here
	Commands:  []*cli.Command{ssmShellCmd, ssmForwardCmd, ssmSshCmd},
}

/*
 *  Flags and functions defined below aren't used directly by the ssmCmd defined in this file, but are shared across
 *  the subcommands used to handle shell, port forwarding and ssh sessions.  Figured this would be a good common
 *  place to put these shared bits to avoid having to search through all of the ssm code files.  But let's be honest,
 *  you still will anyway :).
 */

var ssmUsePluginFlag = &cli.BoolFlag{
	Name:    "plugin",
	Aliases: []string{"P"},
	Usage:   "Use the SSM session plugin instead of built-in code",
}

//nolint:gocognit
func doSsmSetup(ctx context.Context, cmd *cli.Command, expectedArgs int) (string, client.AwsClient, error) {
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

	saveStsCredentials(cmd, profile, creds)

	if cmd.Bool(expFlag.Name) || cmd.Bool(whoamiFlag.Name) {
		if cmd.Bool(expFlag.Name) {
			printCredExpiration(creds)
		}

		if cmd.Bool(whoamiFlag.Name) {
			if err = printCredIdentity(sts.NewFromConfig(c.ConfigProvider())); err != nil {
				return "", nil, err
			}
		}
	}

	target := cmd.Args().First()
	if target == profile {
		target = cmd.Args().Get(1)
	}

	return target, c, nil
}

func execSsmPlugin(cfg aws.Config, in *ssm.StartSessionInput) error {
	s := ssm.NewFromConfig(cfg)
	out, err := s.StartSession(context.Background(), in)
	if err != nil {
		return err
	}

	var inJ, outJ []byte
	outJ, err = json.Marshal(out)
	if err != nil {
		return err
	}

	inJ, err = json.Marshal(in)
	if err != nil {
		return err
	}

	var ep aws.Endpoint                                                                                   //nolint:staticcheck
	ep, err = ssm.NewDefaultEndpointResolver().ResolveEndpoint(cfg.Region, ssm.EndpointResolverOptions{}) //nolint:staticcheck
	if err != nil {
		return err
	}

	// the empty string after StartSession would normally be where a named profile would be specified, but
	// that's unnecessary when wrapping with aws-runas, which handles profile and credential stuff for us
	// session-manager-plugin executable must be found in PATH
	c := exec.Command("session-manager-plugin", string(outJ), cfg.Region, "StartSession", "", string(inJ), ep.URL) //nolint:gosec
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	log.Debugf("COMMAND: %s", c.String())
	return c.Run()
}
