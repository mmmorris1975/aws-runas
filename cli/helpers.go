package cli

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	awsclient "github.com/aws/aws-sdk-go/aws/client"
	awscreds "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/dustin/go-humanize"
	"github.com/mmmorris1975/aws-runas/client"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/urfave/cli/v2"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"
)

// if the 1st command line arg doesn't exist, check env vars for profile name
// if a profile env var is found, unset them to avoid messing with the AWS Session setup
// and expose the profile name as a new env var (AWSRUNAS_PROFILE)
//
// returns the name of the profile discovered via the command line or env vars, and the
// resolved AwsConfig object for the discovered profile (or source profile, if requested).
// Error will be returned for a failure of configuration resolution.
func resolveConfig(ctx *cli.Context, expectedArgs int) (string, *config.AwsConfig, error) {
	profile := checkProfileArgs(ctx, expectedArgs)

	// profile might possibly be omitted from the command line as well, in which case, we'll check the
	// environment for the standard AWS env vars for profile values
	if len(profile) < 1 {
		profile = checkProfileEnv()
	}

	cfg, err := configResolver.Config(profile)
	if err != nil {
		return profile, nil, err
	}

	// return config for source profile, if any
	if ctx.Bool(sessionFlag.Name) && cfg.SourceProfile() != nil {
		jr := cfg.JumpRoleArn
		cfg = cfg.SourceProfile()

		// use SAML/OIDC jump role setting as the session credentials, if found
		if len(jr) > 0 {
			cfg.RoleArn = jr
			cfg.JumpRoleArn = "" // unset jump role so we get the unwrapped SAML/OIDC client
		}
	}

	cfg.MergeIn(cmdlineCfg) // I think this is a good idea??
	return profile, cfg, nil
}

func checkProfileArgs(ctx *cli.Context, expectedArgs int) string {
	// if we got here via a top-level flag, ctx.Args() could be empty, must check 1 level up via
	// ctx.Lineage() for the value
	var profile string
	if ctx.NArg() >= expectedArgs {
		profile = ctx.Args().First()
	} else if ctx.NArg() == 0 && len(ctx.Lineage()) > 2 {
		next := ctx.Lineage()[1]
		if next.NArg() >= expectedArgs {
			profile = next.Args().First()

			// the 1st arg of the parent context matches our current command name.  It's entirely
			// possible that someone names a profile the same as the subcommand name, but we'll go
			// on the assumption that what really happened is that the profile is coming in via an
			// environment variable, and we should return and allow the env var to be used
			if profile == ctx.Command.Name {
				return ""
			}
		}
	}
	return profile
}

// Check for AWS profile env vars if nothing was found on the command line.  This must be done because we
// need to know the source profile setting if any of these env vars specify a profile which uses a role.
func checkProfileEnv() string {
	profile := os.Getenv("AWS_PROFILE")
	if len(profile) < 1 {
		profile = os.Getenv("AWS_DEFAULT_PROFILE")
	}

	// explicitly unset AWS profile env vars so they don't get in the way of AWS Session setup
	_ = os.Unsetenv("AWS_PROFILE")
	_ = os.Unsetenv("AWS_DEFAULT_PROFILE")

	if len(profile) > 0 && !arn.IsARN(profile) {
		_ = os.Setenv("AWSRUNAS_PROFILE", profile)
	}
	return profile
}

// configure signal handler to make runas ignore (pass through) the below signals.
// used by SSM shell, and 'wrapped' commands to pass signals to the called commands.
// code calling this function should configure a defer function to reset the signal handling, if desired.
func installSignalHandler() chan os.Signal {
	sigCh := make(chan os.Signal, 3)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGQUIT)
	go func() {
		for {
			sig := <-sigCh
			log.Debugf("Got signal: %s", sig.String())
		}
	}()
	return sigCh
}

// we're only clearing the cached AWS STS credentials and any Web Identity Token cache for the profile. Things like
// external IdP session state will not be cleaned up via this process. (Nor do I believe they should be).  There is
// a non-zero chance when dealing with external IdP clients that you may need to re-authenticate if your IdP session
// expired.  I believe it's more likely to happen with Web Identity clients as fetching identity information is part
// of the client setup.
//
// for things where we don't deal with sts credentials (-l, -r, -u, -D, password sub command), or could possibly
// deal with a lot of them (ec2 and ecs metadata services), this wouldn't make sense to use.
func refreshCreds(c client.AwsClient) {
	if err := c.ClearCache(); err != nil {
		log.Warningf("failed to clear cache: %v", err)
	}
}

func printCredExpiration(creds *credentials.Credentials) {
	var msg string

	exp := creds.Expiration
	if exp.IsZero() {
		// honestly, this should _never_ happen, since it goes against the entire reason for this program
		msg = "credentials will not expire"
	} else {
		format := exp.Format("2006-01-02 15:04:05")
		hmn := humanize.Time(exp)

		tense := "will expire"
		if exp.Before(time.Now()) {
			// will probably never see this either, since expired creds would likely be refreshed before we get here
			tense = "expired"
		}

		msg = fmt.Sprintf("Credentials %s on %s (%s)", tense, format, hmn)
	}

	_, _ = fmt.Fprintln(os.Stderr, msg)
}

func printCredIdentity(cfg awsclient.ConfigProvider, creds *credentials.Credentials) error {
	credOverlay := awscreds.NewStaticCredentialsFromCreds(creds.Value())
	id, err := sts.New(cfg, new(aws.Config).WithCredentials(credOverlay)).
		GetCallerIdentity(new(sts.GetCallerIdentityInput))
	if err != nil {
		return err
	}

	log.Infof("%+v", id)
	return nil
}

func bashCompleteProfile(ctx *cli.Context) {
	if ctx.NArg() > 0 {
		return
	}

	p, err := config.DefaultIniLoader.Profiles()
	if err != nil {
		log.Debugf("completion error: %v", err)
		return
	}

	var i int
	vals := make([]string, len(p))
	for k := range p {
		vals[i] = k
		i++
	}
	sort.Strings(vals)

	for _, v := range vals {
		fmt.Println(v)
	}
}
