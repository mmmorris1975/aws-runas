package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/mbndr/logo"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	VERSION     = "0.1.0"
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
	version         *bool
	profile         *string
	duration        *time.Duration
	cmd             *[]string
	defaultDuration = time.Duration(12) * time.Hour
	cacheDir        = filepath.Dir(defaults.SharedCredentialsFilename())
	logLevel	= logo.WARN
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
		profileArgDesc  = "name of profile"
		cmdArgDesc      = "command to execute using configured profile"
	)

	duration = kingpin.Flag("duration", durationArgDesc).Short('d').Default(defaultDuration.String()).Duration()
	listRoles = kingpin.Flag("list-roles", listRoleArgDesc).Short('l').Bool()
	listMfa = kingpin.Flag("list-mfa", listMfaArgDesc).Short('m').Bool()
	showExpire = kingpin.Flag("expiration", showExpArgDesc).Short('e').Bool()
	sesCreds = kingpin.Flag("session", sesCredArgDesc).Short('s').Bool()
	refresh = kingpin.Flag("refresh", refreshArgDesc).Short('r').Bool()
	verbose = kingpin.Flag("verbose", verboseArgDesc).Short('v').Bool()
	profile = kingpin.Arg("profile", profileArgDesc).Default("default").String()
	cmd = CmdArg(kingpin.Arg("cmd", cmdArgDesc))

	kingpin.Version(VERSION)
	kingpin.CommandLine.VersionFlag.Short('V')
	kingpin.CommandLine.HelpFlag.Short('h')
	kingpin.CommandLine.Help = cmdDesc
}

func dedupAndSort(ary *[]string) *[]string {
	m := make(map[string]bool)

	// dedup
	for _, v := range *ary {
		trimV := strings.TrimSpace(v)
		if len(trimV) > 0 {
			m[trimV] = true
		}
	}

	// array-ify
	i := 0
	newAry := make([]string, len(m))
	for k := range m {
		newAry[i] = k
		i++
	}

	// sort & return
	sort.Strings(newAry)
	return &newAry
}

func printCredentials(creds credentials.Value) {
	exportToken := "export"
	switch runtime.GOOS {
	case "windows":
		exportToken = "set"
	}

	fmt.Printf("%s %s='%s'\n", exportToken, "AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	fmt.Printf("%s %s='%s'\n", exportToken, "AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	fmt.Printf("%s %s='%s'\n", exportToken, "AWS_SESSION_TOKEN", creds.SessionToken)
	fmt.Printf("%s %s='%s'\n", exportToken, "AWS_SECURITY_TOKEN", creds.SessionToken)
}

func main() {
	kingpin.Parse()

	if *verbose {
		logLevel = logo.DEBUG
	}

	log := logo.NewSimpleLogger(os.Stderr, logLevel, "aws-runas.main", true)

	if *duration < minDuration || *duration > maxDuration {
		log.Warnf("Duration should be between %s and %s, using default of %s",
			minDuration.String(), maxDuration.String(), defaultDuration.String())
		duration = &defaultDuration
	}

	// These are magic words to change AssumeRole credential expiration
	stscreds.DefaultDuration = time.Duration(1) * time.Hour

	log.Debugf("PROFILE: %s", *profile)

	// This is how to get the MFA and AssumeRole config for a given profile.
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState:       session.SharedConfigEnable,
		Profile:                 *profile,
		AssumeRoleTokenProvider: stscreds.StdinTokenProvider,
	}))

	switch {
	case *listMfa:
		log.Debug("List MFA")
		s := iam.New(sess)

		res, err := s.ListMFADevices(&iam.ListMFADevicesInput{})
		if err != nil {
			log.Fatalf("%v", err)
		}

		fmt.Printf("%s\n", *res.MFADevices[0].SerialNumber)
	case *listRoles:
		log.Debug("List Roles")
		roles := make([]string, 0)
		s := iam.New(sess)

		u, err := s.GetUser(&iam.GetUserInput{})
		if err != nil {
			log.Fatalf("%v", err)
		}

		userName := *u.User.UserName
		log.Debugf("USER: %s", userName)

		urg := UserRoleGetter{Client: s}
		roles = append(roles, *urg.FetchRoles(userName)...)

		i := iam.ListGroupsForUserInput{UserName: &userName}
		grg := GroupRoleGetter{Client: s}
		truncated := true
		for truncated {
			g, err := s.ListGroupsForUser(&i)
			if err != nil {
				log.Errorf("%v", err)
				break
			}

			if *verbose {
				for x, grp := range g.Groups {
					log.Debugf("GROUP[%d]: %s", x, *grp.GroupName)
				}
			}
			roles = append(roles, *grg.FetchRoles(g.Groups...)...)

			truncated = *g.IsTruncated
			if truncated {
				i.Marker = g.Marker
			}
		}

		fmt.Printf("Available role ARNs for %s (%s)\n", userName, *u.User.Arn)
		for _, v := range *dedupAndSort(&roles) {
			fmt.Printf("  %s\n", v)
		}
	default:
		cfgParser := AWSConfigParser{ Log: logo.NewSimpleLogger(os.Stderr, logLevel, "aws-runas.AWSConfigParser", true) }
		profile_cfg, err := cfgParser.GetProfile(profile)
		if err != nil {
			log.Fatalf("unable to get configuration for profile '%s': %+v", *profile, err)
		}

		credProvider := CachingSessionTokenProvider{
			Profile:  profile_cfg.SourceProfile,
			Duration: *duration,
		}

		if len(profile_cfg.MfaSerial) > 0 {
			credProvider.MfaSerial = profile_cfg.MfaSerial
		}

		if *refresh {
			os.Remove(credProvider.CacheFile())
		}

		p := credentials.NewCredentials(&credProvider)
		creds, err := p.Get()
		if err != nil {
			log.Fatalf("unable to get SessionToken credentials: +%v", err)
		}

		if *showExpire {
			exp_t := credProvider.ExpirationTime()
			fmt.Printf("Session credentials will expire on %s (%s)\n", exp_t, exp_t.Sub(time.Now()).Round(time.Second))
			os.Exit(0)
		}

		if !*sesCreds {
			creds, err = credProvider.AssumeRole(profile_cfg)
			if err != nil {
				log.Fatalf("error doing AssumeRole: %+v", err)
			}
		}

		if len(*cmd) > 1 {
			os.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
			os.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
			if len(creds.SessionToken) > 0 {
				os.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
				os.Setenv("AWS_SECURITY_TOKEN", creds.SessionToken)
			}

			c := exec.Command((*cmd)[0], (*cmd)[1:]...)
			c.Stdin = os.Stdin
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr

			err := c.Run()
			if err != nil {
				log.Fatalf("%v", err)
			}
		} else {
			printCredentials(creds)
		}
	}
}
