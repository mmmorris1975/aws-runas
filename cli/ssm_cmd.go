package cli

import (
	"encoding/json"
	awsclient "github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/mmmorris1975/aws-runas/client"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/urfave/cli/v2"
	"os"
	"os/exec"
)

var ssmCmd = &cli.Command{
	Name:        "ssm",
	Usage:       "Helpful shortcuts for working with SSM sessions",
	ArgsUsage:   " ", // this hides the default '[arguments...]' help text output, since we don't use command args here
	Subcommands: []*cli.Command{ssmShellCmd, ssmForwardCmd, ssmSshCmd},
}

/*
 *  Flags and functions defined below aren't used directly by the ssmCmd defined in this file, but are shared across
 *  the subcommands used to handle shell, port forwarding and ssh sessions.  Figured this would be a good common
 *  place to put these shared bits to avoid having to search through all of the ssm code files.  But let's be honest,
 *  you still will anyway :)
 */

var ssmUsePluginFlag = &cli.BoolFlag{
	Name:    "plugin",
	Aliases: []string{"P"},
	Usage:   "Use the SSM session plugin instead of built-in code",
}

func doSsmSetup(ctx *cli.Context, expectedArgs int) (string, client.AwsClient, error) {
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
			if err = printCredIdentity(c.ConfigProvider(), creds); err != nil {
				return "", nil, err
			}
		}
	}

	target := ctx.Args().First()
	if target == profile {
		target = ctx.Args().Get(1)
	}

	return target, c, nil
}

func execSsmPlugin(cfg awsclient.ConfigProvider, in *ssm.StartSessionInput) error {
	s := ssm.New(cfg)
	out, err := s.StartSession(in)
	if err != nil {
		return err
	}

	outJ, err := json.Marshal(out)
	if err != nil {
		return err
	}

	inJ, err := json.Marshal(in)
	if err != nil {
		return err
	}

	// the empty string after StartSession would normally be where a named profile would be specified, but
	// that's unnecessary when wrapping with aws-runas, which handles profile and credential stuff for us
	// session-manager-plugin executable must be found in PATH
	c := exec.Command("session-manager-plugin", string(outJ), s.SigningRegion, "StartSession", "", string(inJ), s.Endpoint)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	log.Debugf("COMMAND: %s", c.String())
	return c.Run()
}
