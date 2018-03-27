package main

import (
	"fmt"
	//"github.com/aws/aws-sdk-go/aws/credentials"
	//"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	//humanize "github.com/dustin/go-humanize"
	"github.com/mbndr/logo"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	//	"os/exec"
	"path/filepath"
	//"runtime"
	//"sort"
	//"strings"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/mmmorris1975/aws-runas/lib"
	"time"
)

const (
	VERSION     = "1.0.0-alpha1"
	minDuration = time.Duration(15) * time.Minute
	maxDuration = time.Duration(36) * time.Hour
)

var (
	listRoles       *bool
	listMfa         *bool
	showExpire      *bool
	sesCreds        *bool
	refresh         *bool
	verbose         *bool
	makeConf        *bool
	updateFlag      *bool
	profile         *string
	mfaArn          *string
	duration        *time.Duration
	cmd             *[]string
	defaultDuration = time.Duration(12) * time.Hour
	cacheDir        = filepath.Dir(defaults.SharedCredentialsFilename())
	logLevel        = logo.WARN
	log             *logo.Logger
)

func init() {
	const (
		cmdDesc         = "Create an environment for interacting with the AWS API using an assumed role"
		durationArgDesc = "duration of the retrieved session token"
		listRoleArgDesc = "list role ARNs you are able to assume"
		listMfaArgDesc  = "list the ARN of the MFA device associated with your account"
		showExpArgDesc  = "Show token expiration time"
		sesCredArgDesc  = "print eval()-able session token info, or run command using session token credentials"
		refreshArgDesc  = "force a refresh of the cached credentials"
		verboseArgDesc  = "print verbose/debug messages"
		profileArgDesc  = "name of profile, or role ARN"
		cmdArgDesc      = "command to execute using configured profile"
		mfaArnDesc      = "ARN of MFA device needed to perform Assume Role operation"
		makeConfArgDesc = "Build an AWS extended switch-role plugin configuration for all available roles"
		updateArgDesc   = "Check for updates to aws-runas"
	)

	duration = kingpin.Flag("duration", durationArgDesc).Short('d').Default(defaultDuration.String()).Duration()
	listRoles = kingpin.Flag("list-roles", listRoleArgDesc).Short('l').Bool()
	listMfa = kingpin.Flag("list-mfa", listMfaArgDesc).Short('m').Bool()
	showExpire = kingpin.Flag("expiration", showExpArgDesc).Short('e').Bool()
	makeConf = kingpin.Flag("make-conf", makeConfArgDesc).Short('c').Bool()
	sesCreds = kingpin.Flag("session", sesCredArgDesc).Short('s').Bool()
	refresh = kingpin.Flag("refresh", refreshArgDesc).Short('r').Bool()
	verbose = kingpin.Flag("verbose", verboseArgDesc).Short('v').Bool()
	mfaArn = kingpin.Flag("mfa-arn", mfaArnDesc).Short('M').String()
	updateFlag = kingpin.Flag("update", updateArgDesc).Short('u').Bool()
	profile = kingpin.Arg("profile", profileArgDesc).Default(os.Getenv("AWS_PROFILE")).String()
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

	//if *duration < minDuration || *duration > maxDuration {
	//	log.Warnf("Duration should be between %s and %s, using default of %s",
	//		minDuration.String(), maxDuration.String(), defaultDuration.String())
	//	duration = &defaultDuration
	//}
	//
	//// These are magic words to change AssumeRole credential expiration
	//stscreds.DefaultDuration = time.Duration(1) * time.Hour

	log.Debugf("PROFILE: %s", *profile)
	sess := defaultAwsSession()

	switch {
	case *listMfa:
		log.Debug("List MFA")
		s := iam.New(sess)

		res, err := s.ListMFADevices(&iam.ListMFADevicesInput{})
		if err != nil {
			log.Fatalf("Error listing MFA devices: %v", err)
		}

		for _, d := range res.MFADevices {
			fmt.Printf("%s\n", *d.SerialNumber)
		}
	case *listRoles, *makeConf:
		u := iamUser(sess)
		userName := *u.UserName

		rg := lib.NewRoleGetter(sess, userName, logLevel)

		if *listRoles {
			log.Debug("List Roles")
			fmt.Printf("Available role ARNs for %s (%s)\n", userName, *u.Arn)
			for _, v := range rg.Roles() {
				fmt.Printf("  %s\n", v)
			}
		}

		if *makeConf {
			log.Debug("Make Configuration Files.")
			// TODO create .aws/config formatted output based on result of rg.Roles()
		}
	case *updateFlag:
		// TODO check github releases page for update
	default:
		//profile_cfg, err := NewAWSProfile(profile, mfaArn)
		//if err != nil {
		//	log.Fatalf("Unable to get configuration for profile '%s': %+v", *profile, err)
		//}
		//
		//credProvider := CachingSessionTokenProvider{
		//	Profile:  profile_cfg.SourceProfile,
		//	Duration: *duration,
		//	Logger:   logo.NewSimpleLogger(os.Stderr, logLevel, "aws-runas.CachingSessionTokenProvider", true),
		//}
		//
		//if len(profile_cfg.MfaSerial) > 0 {
		//	credProvider.MfaSerial = profile_cfg.MfaSerial
		//}
		//
		//if *refresh {
		//	os.Remove(credProvider.CacheFile())
		//}
		//
		//p := credentials.NewCredentials(&credProvider)
		//creds, err := p.Get()
		//if err != nil {
		//	log.Fatalf("Unable to get SessionToken credentials: +%v", err)
		//}
		//
		//if *showExpire {
		//	exp_t := credProvider.ExpirationTime()
		//	fmt_t := exp_t.Format("2006-01-02 15:04:05")
		//	hmn_t := humanize.Time(exp_t)
		//
		//	sentance_tense := "will expire"
		//	if exp_t.Before(time.Now()) {
		//		sentance_tense = "expired"
		//	}
		//	fmt.Fprintf(os.Stderr, "Session credentials %s on %s (%s)\n", sentance_tense, fmt_t, hmn_t)
		//}
		//
		//if !*sesCreds {
		//	creds, err = credProvider.AssumeRole(profile_cfg)
		//	if err != nil {
		//		log.Fatalf("Error doing AssumeRole: %+v", err)
		//	}
		//}
		//
		//if len(*cmd) > 0 {
		//	os.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
		//	os.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
		//	if len(creds.SessionToken) > 0 {
		//		os.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
		//		os.Setenv("AWS_SECURITY_TOKEN", creds.SessionToken)
		//	}
		//
		//	c := exec.Command((*cmd)[0], (*cmd)[1:]...)
		//	c.Stdin = os.Stdin
		//	c.Stdout = os.Stdout
		//	c.Stderr = os.Stderr
		//
		//	err := c.Run()
		//	if err != nil {
		//		log.Debug("Error running command")
		//		log.Fatalf("%v", err)
		//	}
		//} else {
		//	printCredentials(creds)
		//}
	}
}

func defaultAwsSession() *session.Session {
	// Doing this kills the ability to use env vars, which may mess
	// with the -M option, requiring the ~/.aws/credentials file
	// Unset AWS credential env vars
	//env := []string{
	//	"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY",
	//	"AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY",
	//	"AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
	//}
	//for _, e := range env {
	//	os.Unsetenv(e)
	//}

	opts := session.Options{
		SharedConfigState:       session.SharedConfigEnable,
		AssumeRoleTokenProvider: stscreds.StdinTokenProvider,
	}

	if profile != nil && len(*profile) > 0 {
		opts.Profile = *profile
	}

	return session.Must(session.NewSessionWithOptions(opts))
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
