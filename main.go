package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/dustin/go-humanize"
	"github.com/mbndr/logo"
	"github.com/mmmorris1975/aws-runas/lib"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	VERSION = "1.0.0-beta2"
)

var (
	listRoles    *bool
	listMfa      *bool
	showExpire   *bool
	sesCreds     *bool
	refresh      *bool
	verbose      *bool
	makeConf     *bool
	updateFlag   *bool
	profile      *string
	mfaArn       *string
	duration     *time.Duration
	roleDuration *time.Duration
	cmd          *[]string
	logLevel     = logo.WARN
	log          *logo.Logger
)

func init() {
	const (
		cmdDesc             = "Create an environment for interacting with the AWS API using an assumed role"
		durationArgDesc     = "duration of the retrieved session token"
		roleDurationArgDesc = "duration of the assume role credentials"
		listRoleArgDesc     = "list role ARNs you are able to assume"
		listMfaArgDesc      = "list the ARN of the MFA device associated with your account"
		showExpArgDesc      = "Show token expiration time"
		sesCredArgDesc      = "print eval()-able session token info, or run command using session token credentials"
		refreshArgDesc      = "force a refresh of the cached credentials"
		verboseArgDesc      = "print verbose/debug messages"
		profileArgDesc      = "name of profile, or role ARN"
		cmdArgDesc          = "command to execute using configured profile"
		mfaArnDesc          = "ARN of MFA device needed to perform Assume Role operation"
		makeConfArgDesc     = "Build an AWS extended switch-role plugin configuration for all available roles"
		updateArgDesc       = "Check for updates to aws-runas"
	)

	duration = kingpin.Flag("duration", durationArgDesc).Short('d').Duration()
	roleDuration = kingpin.Flag("role-duration", roleDurationArgDesc).Short('a').Duration()
	listRoles = kingpin.Flag("list-roles", listRoleArgDesc).Short('l').Bool()
	listMfa = kingpin.Flag("list-mfa", listMfaArgDesc).Short('m').Bool()
	showExpire = kingpin.Flag("expiration", showExpArgDesc).Short('e').Bool()
	makeConf = kingpin.Flag("make-conf", makeConfArgDesc).Short('c').Bool()
	sesCreds = kingpin.Flag("session", sesCredArgDesc).Short('s').Bool()
	refresh = kingpin.Flag("refresh", refreshArgDesc).Short('r').Bool()
	verbose = kingpin.Flag("verbose", verboseArgDesc).Short('v').Bool()
	mfaArn = kingpin.Flag("mfa-arn", mfaArnDesc).Short('M').String()
	updateFlag = kingpin.Flag("update", updateArgDesc).Short('u').Bool()

	// if AWS_PROFILE env var is NOT set, it MUST be 1st non-flag arg
	// if AWS_PROFILE env var is set, all non-flag args will be treated as cmd
	if v, ok := os.LookupEnv("AWS_PROFILE"); !ok {
		profile = kingpin.Arg("profile", profileArgDesc).String()
	} else {
		profile = aws.String(v)
	}

	cmd = CmdArg(kingpin.Arg("cmd", cmdArgDesc))

	kingpin.Version(VERSION)
	kingpin.CommandLine.VersionFlag.Short('V')
	kingpin.CommandLine.HelpFlag.Short('h')
	kingpin.CommandLine.Help = cmdDesc
}

func main() {
	// Tell kingpin to stop parsing flags once we start processing 'cmd', allows something like:
	// `aws-runas --verbose profile command -a --long_arg`
	// without needing an explicit `--` between 'profile' and 'cmd'
	kingpin.CommandLine.Interspersed(false)
	kingpin.Parse()

	if *verbose {
		logLevel = logo.DEBUG
	}
	log = logo.NewSimpleLogger(os.Stderr, logLevel, "aws-runas.main", true)

	log.Debugf("PROFILE: %s", *profile)
	sess := lib.AwsSession(*profile)

	cm, err := lib.NewAwsConfigManager(&lib.ConfigManagerOptions{LogLevel: logLevel})
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	switch {
	case *listMfa:
		log.Debug("List MFA")
		mfa, err := lib.LookupMfa(sess)
		if err != nil {
			log.Fatalf("Error retrieving MFA info: %v", err)
		}

		for _, d := range mfa {
			fmt.Printf("%s\n", *d.SerialNumber)
		}
	case *listRoles, *makeConf:
		u := iamUser(sess)
		userName := *u.UserName

		rg := lib.NewAwsRoleGetter(sess, userName, &lib.RoleGetterOptions{LogLevel: logLevel})
		roles := rg.Roles()

		if *listRoles {
			log.Debug("List Roles")
			fmt.Printf("Available role ARNs for %s (%s)\n", userName, *u.Arn)
			for _, v := range roles {
				fmt.Printf("  %s\n", v)
			}
		}

		if *makeConf {
			log.Debug("Make Configuration Files.")
			var mfa *string
			if mfaArn != nil && len(*mfaArn) > 0 {
				// MFA arn provided by cmdline option
				mfa = mfaArn
			} else {
				m, err := lib.LookupMfa(sess)
				if err != nil {
					log.Errorf("MFA lookup failed, will not configure MFA: %v", err)
				}

				if len(m) > 0 {
					// use 1st MFA device found
					mfa = m[0].SerialNumber
				}
			}

			if err := cm.BuildConfig(roles, mfa); err != nil {
				log.Fatalf("Error building config file: %v", err)
			}
		}
	case *updateFlag:
		log.Debug("Update check")
		if err := lib.VersionCheck(VERSION); err != nil {
			log.Debugf("Error from VersionCheck(): %v", err)
		}
	default:
		p, err := awsProfile(cm, *profile)
		if err != nil {
			log.Fatalf("Error building profile: %v", err)
		}

		// Add command-line option overrides
		if duration != nil && (*duration).Nanoseconds() > 0 {
			p.SessionDuration = *duration
		}

		if roleDuration != nil && (*roleDuration).Nanoseconds() > 0 {
			p.CredDuration = *roleDuration
		}

		if mfaArn != nil && len(*mfaArn) > 0 {
			p.MfaSerial = *mfaArn
		}
		log.Debugf("RESOLVED PROFILE: %+v", p)

		opts := lib.SessionTokenProviderOptions{
			LogLevel:             logLevel,
			SessionTokenDuration: p.SessionDuration,
			MfaSerial:            p.MfaSerial,
		}
		t, err := lib.NewSessionTokenProvider(p, &opts)
		if err != nil {
			log.Fatalf("Unable to build credential provider: %v", err)
		}

		if *refresh {
			os.Remove(t.CacheFile())
		}

		if *showExpire {
			exp_t := t.ExpirationTime()
			fmt_t := exp_t.Format("2006-01-02 15:04:05")
			hmn_t := humanize.Time(exp_t)

			tense := "will expire"
			if exp_t.Before(time.Now()) {
				tense = "expired"
			}
			fmt.Fprintf(os.Stderr, "Session credentials %s on %s (%s)\n", tense, fmt_t, hmn_t)
		}

		var creds credentials.Value
		if *sesCreds || len(p.RoleArn.Resource) < 1 {
			log.Debugf("Getting SESSION TOKEN credentials")
			c := credentials.NewCredentials(t)
			creds, err = c.Get()
			if err != nil {
				log.Fatalf("Unable to get SessionToken credentials: %v", err)
			}
		} else {
			log.Debugf("Getting ASSUME ROLE credentials")
			in := assumeRoleInput(p)
			res, err := t.AssumeRole(in)
			if err != nil {
				log.Fatalf("Error doing AssumeRole: %+v", err)
			}
			c := res.Credentials
			creds = credentials.Value{
				AccessKeyID:     *c.AccessKeyId,
				SecretAccessKey: *c.SecretAccessKey,
				SessionToken:    *c.SessionToken,
				ProviderName:    "CachedCredentialsProvider",
			}
		}

		updateEnv(creds, p.Region)

		if len(*cmd) > 0 {
			c := exec.Command((*cmd)[0], (*cmd)[1:]...)
			c.Stdin = os.Stdin
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr

			err := c.Run()
			if err != nil {
				log.Debug("Error running command")
				log.Fatalf("%v", err)
			}
		} else {
			printCredentials()
		}
	}
}

func assumeRoleInput(p *lib.AWSProfile) *sts.AssumeRoleInput {
	i := new(sts.AssumeRoleInput)
	if p.CredDuration.Seconds() == 0 {
		i.DurationSeconds = aws.Int64(int64(lib.ASSUME_ROLE_DEFAULT_DURATION.Seconds()))
	} else {
		i.DurationSeconds = aws.Int64(int64(p.CredDuration.Seconds()))
	}

	if len(p.RoleArn.String()) > 0 {
		i.RoleArn = aws.String(p.RoleArn.String())
	}

	if len(p.RoleSessionName) > 0 {
		i.RoleSessionName = aws.String(p.RoleSessionName)
	}

	if len(p.ExternalId) > 0 {
		i.ExternalId = aws.String(p.ExternalId)
	}

	return i
}

func updateEnv(creds credentials.Value, region string) {
	// Explicitly unset AWS_PROFILE to avoid unintended consequences
	os.Unsetenv("AWS_PROFILE")

	// Pass AWS_REGION through if it was set in our env, or found in config.
	// Ensure that called program gets the expected region
	if len(region) > 0 {
		os.Setenv("AWS_REGION", region)
	}

	os.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)

	// If session token creds were returned, set them. Otherwise explicitly
	// unset them to keep the sdk from getting confused.  AFAIK, we should
	// always have SessionTokens, since our entire process revolves around them.
	// But always code defensively
	if len(creds.SessionToken) > 0 {
		os.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
		os.Setenv("AWS_SECURITY_TOKEN", creds.SessionToken)
	} else {
		os.Unsetenv("AWS_SESSION_TOKEN")
		os.Unsetenv("AWS_SECURITY_TOKEN")
	}
}

func iamUser(s *session.Session) *iam.User {
	i := iam.New(s)

	u, err := i.GetUser(new(iam.GetUserInput))
	if err != nil {
		log.Fatalf("Error getting IAM user info: %v", err)
	}

	log.Debugf("USER: %+v", u)
	return u.User
}

func awsProfile(cm lib.ConfigManager, name string) (*lib.AWSProfile, error) {
	var p *lib.AWSProfile

	a, err := arn.Parse(name)
	if err != nil {
		p, err = cm.GetProfile(aws.String(name))
		if err != nil {
			return nil, fmt.Errorf("unable to get configuration for profile '%s': %v", name, err)
		}
	} else {
		if strings.HasPrefix(a.String(), lib.IAM_ARN) {
			// Even though we were passed a role ARN, attempt profile info lookup
			// so we can capture any default configuration. (Ignore any errors)
			p, _ = cm.GetProfile(aws.String(a.String()))
			p.RoleArn = a
		} else {
			return nil, fmt.Errorf("profile argument is not an IAM role ARN")
		}
	}

	return p, nil
}

func printCredentials() {
	format := "%s %s='%s'\n"
	exportToken := "export"
	switch runtime.GOOS {
	case "windows":
		exportToken = "set"
	}

	envVars := []string{
		"AWS_REGION",
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
	}

	for _, v := range envVars {
		val, ok := os.LookupEnv(v)
		if ok {
			fmt.Printf(format, exportToken, v, val)
		}
	}
}
