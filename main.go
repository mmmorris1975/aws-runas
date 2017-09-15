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
)

const VERSION = "0.0.1"

var (
	listRoles *bool
	listMfa   *bool
	verbose   *bool
	version   *bool
	profile   *string
	cmd       *[]string
)

func init() {
	const (
		cmdDesc         = "Create an environment for interacting with the AWS API using an assumed role"
		listRoleArgDesc = "list role ARNs you are able to assume"
		listMfaArgDesc  = "list the ARN of the MFA device associated with your account"
		verboseArgDesc  = "print verbose/debug messages"
		profileArgDesc  = "name of profile"
		cmdArgDesc      = "command to execute using configured profile"
	)

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

	if *verbose {
		log.Printf("DEBUG PROFILE: %s\n", *profile)
	}

	// This seems to be the way in to get the MFA and AssumeRole config for a given profile.
	// (At least without having to figure out all of the config locations in your own code!)
	// However, since the underlying provider data isn't exported (not even stuff like Role
	// or MFA token ARN), we can't manipulate the settings for the provider (specifically
	// the cred expiration time for AssumeRole) before calling Get() to generate our credentials
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
		// TODO process user roles (in parallel)
		urg := UserRoleGetter{Client: s}
		roles = append(roles, *urg.GetInlineRoles(userName)...)
		roles = append(roles, *urg.GetAttachedRoles(userName)...)

		i := iam.ListGroupsForUserInput{UserName: &userName}
		grg := GroupRoleGetter{Client: s}
		truncated := true
		for truncated {
			g, err := s.ListGroupsForUser(&i)
			if err != nil {
				log.Printf("ERROR %v\n", err)
				break
			}

			// TODO process group entries for role data (in parallel)
			for x, grp := range g.Groups {
				if *verbose {
					log.Printf("DEBUG GROUP[%d]: %s\n", x, *grp.GroupName)
				}
				roles = append(roles, *grg.GetInlineRoles(*grp.GroupName)...)
				roles = append(roles, *grg.GetAttachedRoles(*grp.GroupName)...)
			}

			truncated = *g.IsTruncated
			if truncated {
				i.Marker = g.Marker
			}
		}

		fmt.Printf("ROLES: %v\n", dedupAndSort(&roles))
	default:
		// MFA happens here, but does not cache credentials beyond the execution of the program.
		// Also, no way to change default MFA cred expiration of 15min *le sigh*
		// Can probably hack up a custom provider to cache the stuff, but there's no
		// way to change that 15 min default expiration time without a patch to the SDK
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
