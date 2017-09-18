package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	VERSION         = "0.0.1"
	minDuration     = time.Duration(15) * time.Minute
	maxDuration     = time.Duration(1) * time.Hour
	defaultDuration = "1h"
)

var (
	listRoles *bool
	listMfa   *bool
	verbose   *bool
	version   *bool
	profile   *string
	duration  *string
	cmd       *[]string
)

func init() {
	const (
		cmdDesc         = "Create an environment for interacting with the AWS API using an assumed role"
		durationArgDesc = "duration of the retrieved session token"
		listRoleArgDesc = "list role ARNs you are able to assume"
		listMfaArgDesc  = "list the ARN of the MFA device associated with your account"
		verboseArgDesc  = "print verbose/debug messages"
		profileArgDesc  = "name of profile"
		cmdArgDesc      = "command to execute using configured profile"
	)

	duration = kingpin.Flag("duration", durationArgDesc).Short('d').Default(defaultDuration).String()
	listRoles = kingpin.Flag("list-roles", listRoleArgDesc).Short('l').Bool()
	listMfa = kingpin.Flag("list-mfa", listMfaArgDesc).Short('m').Bool()
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

func main() {
	kingpin.Parse()
	duration_d, _ := time.ParseDuration(*duration)

	if duration_d < minDuration || duration_d > maxDuration {
		log.Printf("WARNING Duration should be between %s and %s, using default of %s\n", minDuration.String(), maxDuration.String(), defaultDuration)
		duration_d, _ = time.ParseDuration(defaultDuration)
	}

	// These are magic words to change AssumeRole credential expiration
	stscreds.DefaultDuration = duration_d

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
		// MFA happens here, but does not cache credentials beyond the execution of the program.
		// TODO - Can probably hack up a custom provider to cache the stuff
		// the credentials struct doesn't provide expiration info (although they are returned by the provider)
		// We'll probably want to add our own expiration field when we write to cache
		creds, err := (*sess.Config).Credentials.Get()

		if err != nil {
			log.Fatalf("ERROR %v\n", err)
		}

		if *verbose {
			log.Printf("DEBUG %+v\n", creds)
		}
		os.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
		os.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
		if len(creds.SessionToken) > 0 {
			os.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
			os.Setenv("AWS_SECURITY_TOKEN", creds.SessionToken)
		}

		if len(*cmd) > 1 {
			if *verbose {
				log.Printf("DEBUG CMD: %v\n", *cmd)
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
			exportToken := "export"
			switch runtime.GOOS {
			case "windows":
				exportToken = "set"
			}

			for _, v := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"} {
				fmt.Printf("%s %s='%s'\n", exportToken, v, os.Getenv(v))
			}
		}
	}
}
