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
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/logging"
	"github.com/mmmorris1975/aws-runas/client"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/metadata"
	"github.com/mmmorris1975/simple-logger/logger"
	"github.com/urfave/cli/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	log           = logger.StdLogger
	opts          = client.DefaultOptions
	clientFactory = client.NewClientFactory(configResolver, opts)
	cmdlineCfg    = new(config.AwsConfig)
	cmdlineCreds  = new(config.AwsCredentials)

	configResolver config.Resolver = config.DefaultResolver.WithLogger(log)
)

// App is the struct used to manage the configuration and behavior for the cli handling library.
var App = &cli.App{
	Usage:     "Create an environment for interacting with the AWS API using an assumed role",
	UsageText: fmt.Sprintf("%s [global options] [subcommand] profile [arguments...]", filepath.Base(os.Args[0])),
	Commands:  []*cli.Command{listCmd, serveCmd, ssmCmd, ecrCmd, passwordCmd, diagCmd, updateCmd},
	Flags:     append(configFlags, append(otherFlags, shortcutFlags...)...),

	UseShortOptionHandling: true,
	EnableBashCompletion:   true,

	BashComplete: func(ctx *cli.Context) {
		if ctx.Bool(mfaFlag.Name) {
			mfaCmd.BashComplete(ctx)
			return
		}

		if ctx.Bool(rolesFlag.Name) {
			rolesCmd.BashComplete(ctx)
			return
		}

		if ctx.Bool(diagFlag.Name) {
			diagCmd.BashComplete(ctx)
			return
		}

		// execute default cli package behavior & profile name completion
		cli.DefaultAppComplete(ctx)
		bashCompleteProfile(ctx)
	},

	Before: func(ctx *cli.Context) error {
		opts.Logger = log

		if verbose, ok := ctx.Value(vFlag.Name).([]bool); ok {
			if len(verbose) > 0 {
				log.SetLevel(logger.DEBUG)

				if len(verbose) > 1 {
					opts.AwsLogLevel = logging.Debug
				}
			}
		}

		// set these flags for both SAML and OIDC properties
		username := ctx.String(usernameFlag.Name)
		provider := ctx.String(providerFlag.Name)

		cmdlineCfg.SamlUsername = username
		cmdlineCfg.SamlProvider = provider
		cmdlineCfg.WebIdentityUsername = username
		cmdlineCfg.WebIdentityProvider = provider

		password := ctx.String(passwordFlag.Name)
		cmdlineCreds.SamlPassword = password
		cmdlineCreds.WebIdentityPassword = password
		opts.CommandCredentials = cmdlineCreds

		return nil
	},

	Metadata: map[string]interface{}{
		"url": "https://github.com/mmmorris1975/aws-runas",
	},

	Action: func(ctx *cli.Context) error {
		// these are now broken out to distinct subcommands, flags are provided for compatibility
		// WARNING - this requires special handling of ctx.Args() in the target command's Action()
		//           method if you want to see any command-line positional args
		if ctx.Bool(mfaFlag.Name) {
			return mfaCmd.Run(ctx)
		}

		if ctx.Bool(rolesFlag.Name) {
			return rolesCmd.Run(ctx)
		}

		if ctx.Bool(updateFlag.Name) {
			return updateCmd.Run(ctx)
		}

		if ctx.Bool(diagFlag.Name) {
			return diagCmd.Run(ctx)
		}

		return execCmd(ctx)
	},
}

//nolint:gochecknoinits // kinda need this here
func init() {
	// override built-in version flag to use -V instead of -v (which we want to use for the verbose flag)
	// maintains consistency with older aws-runas versions
	cli.VersionFlag = &cli.BoolFlag{
		Name:    "version",
		Aliases: []string{"V"},
		Usage:   "print the version",
	}
}

//nolint:funlen,gocognit,gocyclo // he's just a long boi ... you should have seen the older versions!
func execCmd(ctx *cli.Context) error {
	profile, cfg, err := resolveConfig(ctx, guessNArgs(ctx.NArg()))
	if err != nil {
		return err
	}

	if !ctx.Args().Present() && len(profile) < 1 {
		log.Errorln("nothing to do!")
		cli.ShowAppHelpAndExit(ctx, 1)
	}

	var c client.AwsClient
	c, err = clientFactory.Get(cfg)
	if err != nil {
		return err
	}

	if ctx.Bool(refreshFlag.Name) {
		refreshCreds(c)
	}

	// do a single-shot credential fetch since there's a number of situations below where we'll use
	// them.  We get the added benefit of having any external IdP authentication handled before
	// possibly heading down the path of starting the ecs credential endpoint
	var creds *credentials.Credentials
	creds, err = c.Credentials()
	if err != nil {
		return err
	}

	if strings.EqualFold(ctx.String(fmtFlag.Name), "json") {
		// truly a one-shot operation, the credentials_process logic will re-exec the command to refresh credentials
		// don't handle any other formatting options, or do any thing else, just poop out json formatted credentials
		// REF: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
		var out []byte
		out, err = creds.CredentialsProcess()
		if err != nil {
			// error will be json marshaling failure
			return err
		}
		fmt.Printf("%s\n", out)
		return nil
	}

	if ctx.Bool(expFlag.Name) {
		printCredExpiration(creds)
	}

	if ctx.Bool(whoamiFlag.Name) {
		if err = printCredIdentity(sts.NewFromConfig(c.ConfigProvider())); err != nil {
			return err
		}
	}

	cmd := ctx.Args().Slice()
	if ctx.Args().First() == profile {
		cmd = ctx.Args().Tail()
	}

	env := buildEnv(cfg.Region, creds)

	if len(cmd) > 0 {
		if ctx.Bool(envFlag.Name) {
			// set credentials in environment, don't start ecs endpoint
			for k, v := range env {
				_ = os.Setenv(k, v)
			}
		} else {
			var ch <-chan bool
			ch, err = runEcsSvc(c, cfg)
			if err != nil {
				return err
			}
			<-ch
			log.Debugf("ECS endpoint ready")
		}

		wrapped := wrapCmd(cmd)
		c := exec.Command(wrapped[0], wrapped[1:]...) //nolint:gosec // it's sort of the whole reason this tool exists
		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr

		installSignalHandler()
		if err = c.Run(); err != nil {
			log.Debug("Error running command")
			return err
		}
	} else {
		printCreds(env)
	}

	return nil
}

func buildEnv(region string, creds *credentials.Credentials) map[string]string {
	// AWS_PROFILE and AWS_DEFAULT_PROFILE are explicitly unset in resolveConfig() if a profile
	// was found in the environment. The env var AWSRUNAS_PROFILE is set to the profile name
	// and pass through that value to downstream programs. No need to manage it here
	env := creds.Env()

	if len(region) > 0 {
		env["AWS_REGION"] = region
		env["AWS_DEFAULT_REGION"] = region
	}

	// If no session token creds were returned, unset them to keep the sdk from getting confused.
	// AFAIK, we should always have SessionTokens, since our entire process revolves around them.
	// But always code defensively
	if len(creds.Token) < 1 {
		_ = os.Unsetenv("AWS_SESSION_TOKEN")
		_ = os.Unsetenv("AWS_SECURITY_TOKEN")
	}

	return env
}

func printCreds(env map[string]string) {
	format := "%s %s='%s'\n"
	exportToken := "export"

	// SHELL env var is not set by default in "normal" Windows cmd.exe and PowerShell sessions.
	// If we detect it, assume we're running under something like git-bash (or maybe Cygwin?)
	// and fall through to using linux-style env var setting syntax
	if runtime.GOOS == "windows" && len(os.Getenv("SHELL")) < 1 {
		exportToken = "set"
		format = "%s %s=%s\n"
	}

	for k, v := range env {
		fmt.Printf(format, exportToken, k, v)
	}

	if v, ok := os.LookupEnv("AWSRUNAS_PROFILE"); ok {
		fmt.Printf(format, exportToken, "AWSRUNAS_PROFILE", v)
	}
}

func runEcsSvc(client client.AwsClient, cfg *config.AwsConfig) (<-chan bool, error) {
	// modify the execution environment to force use of ECS credential URL
	unsetEnv := []string{
		"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY",
		"AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY",
		"AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
	}
	for _, e := range unsetEnv {
		_ = os.Unsetenv(e)
	}

	// AWS_CREDENTIAL_PROFILES_FILE is a Java SDK specific env var for the credential file location
	for _, v := range []string{"AWS_SHARED_CREDENTIALS_FILE", "AWS_CREDENTIAL_PROFILES_FILE"} {
		_ = os.Setenv(v, os.DevNull)
	}

	in := &metadata.Options{
		Path:        metadata.DefaultEcsCredPath,
		Profile:     cfg.ProfileName,
		Logger:      log,
		AwsLogLevel: opts.AwsLogLevel,
	}

	// since this is internal consumption only, use a random port and default path.
	mcs, err := metadata.NewMetadataCredentialService("127.0.0.1:0", in)
	if err != nil {
		return nil, err
	}

	ep := fmt.Sprintf("http://%s%s", mcs.Addr().String(), in.Path)
	_ = os.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", ep)
	ch := make(chan bool, 1)
	go mcs.RunNoApi(client, cfg, ch) //nolint:errcheck
	return ch, nil
}

// If on a non-windows platform, with the SHELL environment variable set, and a call to exec.LookPath()
// for 1st element of the command fails, run the command in a sub-shell so we can support shell aliases.
//nolint:gocognit
func wrapCmd(cmd []string) []string {
	var newCmd []string
	if cmd == nil || len(cmd) < 1 {
		return newCmd
	}

	if runtime.GOOS != "windows" {
		// Add other shells here as need arises, the only requirement being it must provide "standard"
		// behavior for the -i and -c options
		shells := []string{"bash", "fish", "zsh", "ksh", "ash", "sh", "dash"}

		c, err := exec.LookPath(cmd[0])
		if len(c) < 1 || err != nil {
			sh := os.Getenv("SHELL")
			for _, s := range shells {
				if strings.HasSuffix(sh, "/"+s) {
					newCmd = []string{sh, "-i", "-c", strings.Join(cmd, " ")}
					break
				}
			}
		}
	}

	// We aren't wrapping the provided command, so use it directly
	if len(newCmd) < 1 {
		newCmd = cmd
	}

	log.Debugf("WRAPPED CMD: %v", newCmd)
	return newCmd
}

// We need to do things a bit differently when dealing with executing a wrapped command.  With the subcommands,
// we have a pretty good handle on the number of expected command line arguments. We inherently can't know the
// number of arguments used for a wrapped command, and shouldn't require/force users to explicitly pass the profile
// name as the 1st command line arg. Here we check for the existence of the env vars for specifying a profile,
// and assume if any are set, we're supposed to use those, and all of the command line arguments are actually
// part of the command.  Pretty sure this preserves the behavior of older aws-runas versions as well.
func guessNArgs(n int) int {
	if len(os.Getenv("AWS_PROFILE")) > 0 || len(os.Getenv("AWS_DEFAULT_PROFILE")) > 0 {
		return n + 1
	}
	return n
}
