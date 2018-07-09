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
	// VERSION - The program version
	VERSION = "1.0.2"
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
	diagFlag     *bool
	profile      *string
	mfaArn       *string
	duration     *time.Duration
	roleDuration *time.Duration
	cmd          *[]string
	log          *logo.Logger
	logLevel     = logo.WARN
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
		diagArgDesc         = "Run diagnostics to gather info to troubleshoot issues"
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
	diagFlag = kingpin.Flag("diagnose", diagArgDesc).Short('D').Bool()

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

	iamUser := iamUser()

	switch {
	case *listMfa:
		log.Debug("List MFA")
		printMfa(sess)
	case *listRoles, *makeConf:
		if iamUser == nil {
			log.Fatalf("Unable to determine IAM user")
		}

		userName := *iamUser.UserName

		rg := lib.NewAwsRoleGetter(sess, userName, &lib.RoleGetterOptions{LogLevel: logLevel})
		roles := rg.Roles()

		if *listRoles {
			log.Debug("List Roles")
			fmt.Printf("Available role ARNs for %s (%s)\n", userName, *iamUser.Arn)
			for _, v := range roles {
				fmt.Printf("  %s\n", v)
			}
		}

		if *makeConf {
			log.Debug("Make Configuration Files.")
			mfa := lookupMfa(sess)

			if err := cm.BuildConfig(roles, mfa); err != nil {
				log.Fatalf("Error building config file: %v", err)
			}
		}
	case *updateFlag:
		log.Debug("Update check")
		if err := lib.VersionCheck(VERSION); err != nil {
			log.Debugf("Error from VersionCheck(): %v", err)
		}
	case *diagFlag:
		var p *lib.AWSProfile
		var err error

		log.Debugf("Diagnostics")
		if profile == nil || len(*profile) == 0 {
			log.Fatalf("Please provide a profile name for gathering diagnostics data")
		} else {
			p, err = awsProfile(cm, *profile, iamUser)
			if err != nil {
				log.Fatalf("Error building profile, possible issue with config file: %v", err)
			}
		}

		if len(p.RoleArn.Resource) > 0 && len(p.SourceProfile) < 1 {
			log.Fatalf("source_profile attribute is required when role_arn is set for profile %s", p.Name)
		}

		if err := lib.RunDiagnostics(p); err != nil {
			log.Fatalf("Issue found: %v", err)
		}
	default:
		p, err := awsProfile(cm, *profile, iamUser)
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

		credProvider := credProvider(p)

		if *refresh {
			os.Remove(credProvider.CacheFile())
		}

		if *showExpire {
			printExpire(credProvider)
		}

		c := credentials.NewCredentials(credProvider)
		creds, err := c.Get()
		if err != nil {
			log.Fatalf("Error getting credentials: %v", err)
		}

		updateEnv(creds, p.Region)

		if len(*cmd) > 0 {
			cmd = wrapCmd(cmd)
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

func wrapCmd(cmd *[]string) *[]string {
	// If on a non-windows platform, with the SHELL environment variable set,
	// and a call to exec.LookPath() for the command fails, run the command in
	// a sub-shell so we can support shell aliases.
	newCmd := make([]string, 0)

	if runtime.GOOS != "windows" {
		c, err := exec.LookPath((*cmd)[0])
		if len(c) < 1 || err != nil {
			sh := os.Getenv("SHELL")
			if strings.HasSuffix(sh, "/bash") || strings.HasSuffix(sh, "/fish") ||
				strings.HasSuffix(sh, "/zsh") || strings.HasSuffix(sh, "/ksh") {
				newCmd = append(newCmd, sh, "-i", "-c")
			}
			// Add other shells here as need arises
		}
	}

	newCmd = append(newCmd, (*cmd)...)
	if log != nil {
		log.Debugf("WRAPPED CMD: %v", newCmd)
	}

	return &newCmd
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
	// Ensure that called program gets the expected region.  Also set
	// AWS_DEFAULT_REGION so awscli works as expected, otherwise it will use
	// any region from the profile (or default, since we're not providing profile)
	if len(region) > 0 {
		os.Setenv("AWS_REGION", region)
		os.Setenv("AWS_DEFAULT_REGION", region)
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

func iamUser() *iam.User {
	i := iam.New(lib.AwsSession(""))

	u, err := i.GetUser(new(iam.GetUserInput))
	if err != nil {
		log.Warnf("Error getting IAM user info: %v", err)
		return nil
	}

	if log != nil {
		log.Debugf("USER: %+v", u)
	}
	return u.User
}

func awsProfile(cm lib.ConfigManager, name string, user *iam.User) (*lib.AWSProfile, error) {
	var p *lib.AWSProfile

	// Lookup default profile name, in case we were not passed a profile,
	// or role_arn as part of the command
	defProfile := session.DefaultSharedConfigProfile
	v, ok := os.LookupEnv("AWS_DEFAULT_PROFILE")
	if ok {
		defProfile = v
	}
	if len(name) < 1 {
		name = defProfile
	}

	a, err := arn.Parse(name)
	if err != nil {
		p, err = cm.GetProfile(aws.String(name))
		if err != nil {
			return nil, fmt.Errorf("unable to get configuration for profile '%s': %v", name, err)
		}

		if len(p.Name) < 1 {
			// helps keep cache file naming sane
			p.Name = defProfile
		}
	} else {
		if strings.HasPrefix(a.String(), lib.IAM_ARN) {
			// Unset AWS_PROFILE here, in case the role ARN came in via environment
			// variable, otherwise is messes up GetProfile
			os.Unsetenv("AWS_PROFILE")
			p, err = cm.GetProfile(aws.String(defProfile))
			if err != nil {
				return nil, err
			}
			p.RoleArn = a
		} else {
			return nil, fmt.Errorf("profile argument is not an IAM role ARN")
		}
	}

	if len(p.RoleSessionName) < 1 {
		p.RoleSessionName = aws.StringValue(user.UserName)
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
		"AWS_REGION", "AWS_DEFAULT_REGION",
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

func printMfa(s *session.Session) {
	mfa, err := lib.LookupMfa(s)
	if err != nil {
		log.Fatalf("Error retrieving MFA info: %v", err)
	}

	for _, d := range mfa {
		fmt.Printf("%s\n", *d.SerialNumber)
	}
}

func lookupMfa(s *session.Session) *string {
	var mfa *string
	if mfaArn != nil && len(*mfaArn) > 0 {
		// MFA arn provided by cmdline option
		mfa = mfaArn
	} else {
		m, err := lib.LookupMfa(s)
		if err != nil {
			log.Errorf("MFA lookup failed, will not configure MFA: %v", err)
		}

		if len(m) > 0 {
			// use 1st MFA device found
			mfa = m[0].SerialNumber
		}
	}
	return mfa
}

func credProvider(p *lib.AWSProfile) lib.SessionTokenProvider {
	opts := lib.CachedCredentialsProviderOptions{
		LogLevel:  logLevel,
		MfaSerial: p.MfaSerial,
	}

	var credProvider lib.SessionTokenProvider
	if *sesCreds || len(p.RoleArn.Resource) < 1 {
		if log != nil {
			log.Debugf("Getting SESSION TOKEN credentials")
		}
		opts.CredentialDuration = p.SessionDuration
		credProvider = lib.NewSessionTokenProvider(p, &opts)
	} else {
		if log != nil {
			log.Debugf("Getting ASSUME ROLE credentials")
		}
		opts.CredentialDuration = p.CredDuration
		credProvider = lib.NewAssumeRoleProvider(p, &opts)
	}
	return credProvider
}

func printExpire(p lib.CachedCredentialProvider) {
	exp := p.ExpirationTime()
	format := exp.Format("2006-01-02 15:04:05")
	hmn := humanize.Time(exp)

	tense := "will expire"
	if exp.Before(time.Now()) {
		tense = "expired"
	}
	fmt.Fprintf(os.Stderr, "Credentials %s on %s (%s)\n", tense, format, hmn)
}
