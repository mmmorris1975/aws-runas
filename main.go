package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
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
)

func init() {
	const (
		cmdDesc         = "Create an environment for interacting with the AWS API using an assumed role"
		durationArgDesc = "duration of the retrieved session token"
		listRoleArgDesc = "list role ARNs you are able to assume"
		listMfaArgDesc  = "list the ARN of the MFA device associated with your account"
		showExpArgDesc  = "Show token expiration time"
		sesCredArgDesc  = "print eval()-able session token info"
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

	if *duration < minDuration || *duration > maxDuration {
		log.Printf("WARNING Duration should be between %s and %s, using default of %s\n",
			minDuration.String(), maxDuration.String(), defaultDuration.String())
		duration = &defaultDuration
	}

	// These are magic words to change AssumeRole credential expiration
	stscreds.DefaultDuration = time.Duration(1) * time.Hour

	if *verbose {
		log.Printf("DEBUG PROFILE: %s\n", *profile)
	}

	// This is how to get the MFA and AssumeRole config for a given profile.
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState:       session.SharedConfigEnable,
		Profile:                 *profile,
		AssumeRoleTokenProvider: stscreds.StdinTokenProvider,
	}))

	switch {
	case *listMfa:
		if *verbose {
			log.Println("DEBUG List MFA")
		}

		s := iam.New(sess)
		res, err := s.ListMFADevices(&iam.ListMFADevicesInput{})
		if err != nil {
			log.Fatalf("ERROR %v\n", err)
		}
		fmt.Printf("%s\n", *res.MFADevices[0].SerialNumber)
	case *listRoles:
		roles := make([]string, 0)
		if *verbose {
			log.Println("DEBUG List Roles")
		}
		s := iam.New(sess)

		u, err := s.GetUser(&iam.GetUserInput{})
		if err != nil {
			log.Fatalf("ERROR %v\n", err)
		}
		userName := *u.User.UserName
		if *verbose {
			log.Printf("DEBUG USER: %s\n", userName)
		}

		urg := UserRoleGetter{Client: s}
		roles = append(roles, *urg.FetchRoles(userName)...)

		i := iam.ListGroupsForUserInput{UserName: &userName}
		grg := GroupRoleGetter{Client: s}
		truncated := true
		for truncated {
			g, err := s.ListGroupsForUser(&i)
			if err != nil {
				log.Printf("ERROR %v\n", err)
				break
			}

			if *verbose {
				for x, grp := range g.Groups {
					log.Printf("DEBUG GROUP[%d]: %s\n", x, *grp.GroupName)
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
		profile_cfg, err := new(AWSConfigParser).GetProfile(profile)
		if err != nil {
			log.Fatalf("ERROR unable to get configuration for profile '%s': %+v", *profile, err)
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
			log.Fatalf("ERROR unable to get SessionToken credentials: +%v", err)
		}

		if *showExpire {
			exp_t := credProvider.ExpirationTime()
			log.Printf("Session credentials will expire on %s (%s)", exp_t, exp_t.Sub(time.Now()).Round(time.Second))
			os.Exit(0)
		}

		if *sesCreds {
			printCredentials(creds)
			os.Exit(0)
		}

		ar_creds, err := credProvider.AssumeRole(profile_cfg)
		if err != nil {
			log.Fatalf("ERROR error doing AssumeRole: %+v", err)
		}

		if len(*cmd) > 1 {
			os.Setenv("AWS_ACCESS_KEY_ID", *ar_creds.AccessKeyId)
			os.Setenv("AWS_SECRET_ACCESS_KEY", *ar_creds.SecretAccessKey)
			if len(creds.SessionToken) > 0 {
				os.Setenv("AWS_SESSION_TOKEN", *ar_creds.SessionToken)
				os.Setenv("AWS_SECURITY_TOKEN", *ar_creds.SessionToken)
			}

			c := exec.Command((*cmd)[0], (*cmd)[1:]...)
			c.Stdin = os.Stdin
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr

			err := c.Run()
			if err != nil {
				log.Fatalf("ERROR %v\n", err)
			}
		} else {
			// AssumeRole credentials are sts.Credentials, convert to credentials.Value to print
			printCredentials(credentials.Value{
				AccessKeyID:     *ar_creds.AccessKeyId,
				SecretAccessKey: *ar_creds.SecretAccessKey,
				SessionToken:    *ar_creds.SessionToken,
			})
		}
	}
}
