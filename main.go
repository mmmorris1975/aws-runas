package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
	"os"
	"os/exec"
	"os/user"
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

func doAssumeRole(ses_creds *credentials.Value, profile_cfg *AWSProfile) (*sts.Credentials, error) {
	username := "__"
	user, err := user.Current()
	if err == nil {
		username = user.Username
	}

	sesName := aws.String(fmt.Sprintf("AWS-RUNAS-%s-%d", username, time.Now().Unix()))
	input := sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(int64(3600)),
		RoleArn:         aws.String(profile_cfg.RoleArn),
		RoleSessionName: sesName,
	}

	sesOpts := session.Options{
		Profile:           profile_cfg.SourceProfile,
		SharedConfigState: session.SharedConfigEnable,
		Config:            aws.Config{Credentials: credentials.NewStaticCredentialsFromCreds(*ses_creds)},
	}
	s := session.Must(session.NewSessionWithOptions(sesOpts))
	sts := sts.New(s)
	res, err := sts.AssumeRole(&input)
	if err != nil {
		log.Fatalf("ERROR error calling AssumeRole: %+v", err)
		return nil, err
	}
	return res.Credentials, nil
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

		cacheFile := filepath.Join(cacheDir, fmt.Sprintf(".aws_session_token_%s", profile_cfg.SourceProfile))

		if *refresh {
			os.Remove(cacheFile)
		}

		// FIXME in theory couldn't we create a SessionTokenProvider which we could plug into credentials.NewCredentials
		// to handle retrieving & caching of the credentials, and provide a way to refresh expired session tokens?
		credProvider := &CredentialsCacherProvider{CacheFilename: cacheFile}
		creds, err := credProvider.Retrieve()
		if err != nil && *verbose {
			log.Printf("DEBUG WARNING Error fetching cached credentials: %+v\n", err)
		}

		if credProvider.IsExpired() {
			ses_duration := int64(duration.Seconds())
			input := sts.GetSessionTokenInput{DurationSeconds: &ses_duration}

			mfa_serial := profile_cfg.MfaSerial
			if len(mfa_serial) > 0 {
				// Prompt for MFA code
				var mfa_code string
				fmt.Print("Enter MFA Code: ")
				fmt.Scanln(&mfa_code)

				input.SerialNumber = &mfa_serial
				input.TokenCode = &mfa_code
			}
			s := sts.New(sess)
			res, err := s.GetSessionToken(&input)
			if err != nil {
				log.Fatalf("ERROR unable to get session token: %+v", err)
			}

			c := CacheableCredentials{
				AccessKeyId:     *res.Credentials.AccessKeyId,
				SecretAccessKey: *res.Credentials.SecretAccessKey,
				SessionToken:    *res.Credentials.SessionToken,
				Expiration:      (*res.Credentials.Expiration).Unix(),
			}
			credProvider.Store(&c)
			creds, _ = credProvider.Retrieve()
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

		if *verbose {
			log.Printf("DEBUG Credentials: %+v\n", creds)
		}

		ar_creds, err := doAssumeRole(&creds, profile_cfg)
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
