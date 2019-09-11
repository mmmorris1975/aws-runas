package main

import (
	"fmt"
	"github.com/alecthomas/kingpin"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/dustin/go-humanize"
	"github.com/mmmorris1975/aws-runas/lib/cache"
	"github.com/mmmorris1975/aws-runas/lib/config"
	credlib "github.com/mmmorris1975/aws-runas/lib/credentials"
	"github.com/mmmorris1975/aws-runas/lib/metadata"
	"github.com/mmmorris1975/aws-runas/lib/ssm"
	"github.com/mmmorris1975/aws-runas/lib/util"
	"github.com/mmmorris1975/simple-logger"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	assumeRoleCachePrefix   = ".aws_assume_role"
	sessionTokenCachePrefix = ".aws_session_token"
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
	ec2MdFlag    *bool
	envFlag      *bool
	profile      *string
	mfaArn       *string
	mfaCode      *string
	duration     *time.Duration
	roleDuration *time.Duration
	ses          *session.Session
	cfg          *config.AwsConfig
	usr          *credlib.AwsIdentity

	exe   *kingpin.CmdClause
	shell *kingpin.CmdClause
	fwd   *kingpin.CmdClause

	execArgs  = new(cmdArgs)
	shellArgs = new(cmdArgs)
	fwdArgs   = new(cmdArgs)

	sigCh = make(chan os.Signal, 3)
	log   = simple_logger.StdLogger
)

type cmdArgs struct {
	profile   *string
	cmd       *[]string
	target    *string
	localPort *uint16
}

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
		ec2ArgDesc          = "Run as mock EC2 metadata service to provide role credentials"
		envArgDesc          = "Pass credentials to program as environment variables"
		mfaCodeDesc         = "MFA token code"
		fwdPortDesc         = "The local port for the forwarded connection"
	)

	// top-level flags
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
	mfaCode = kingpin.Flag("otp", mfaCodeDesc).Short('o').String()
	updateFlag = kingpin.Flag("update", updateArgDesc).Short('u').Bool()
	diagFlag = kingpin.Flag("diagnose", diagArgDesc).Short('D').Bool()
	ec2MdFlag = kingpin.Flag("ec2", ec2ArgDesc).Bool()
	envFlag = kingpin.Flag("env", envArgDesc).Short('E').Bool()

	// Can not use Command() if you also have top-level Arg()s defined, so wrap "typical" behavior as the default command
	// so users can continue to use the tool as before
	exe = kingpin.Command("exec", "run the provided command").Default().Hidden() // to hide or not to hide, that is the question
	execArgs.profile = profileEnvArg(exe, profileArgDesc)
	execArgs.cmd = exe.Arg("cmd", cmdArgDesc).Strings()

	shell = kingpin.Command("shell", "Start an SSM shell session to the given target")
	shellArgs.profile = profileEnvArg(shell, profileArgDesc)
	shellArgs.target = shell.Arg("target", "The EC2 instance to connect via SSM").String()

	fwd = kingpin.Command("forward", "Start an SSM port-forwarding session to the given target").Alias("fwd")
	fwdArgs.localPort = fwd.Flag("port", fwdPortDesc).Short('p').Default("0").Uint16()
	fwdArgs.profile = profileEnvArg(fwd, profileArgDesc)
	fwdArgs.target = fwd.Arg("target", "The EC2 instance id and remote port, separated by ':'").String()

	kingpin.Version(Version)
	kingpin.CommandLine.VersionFlag.Short('V')
	kingpin.CommandLine.HelpFlag.Short('h')
	kingpin.CommandLine.Help = cmdDesc
	kingpin.CommandLine.Interspersed(false)
}

func main() {
	p := kingpin.Parse()
	profile = coalesce(execArgs.profile, shellArgs.profile, fwdArgs.profile, aws.String("default"))

	if *verbose {
		log.SetLevel(simple_logger.DEBUG)
	}

	resolveConfig()
	log.Debugf("CONFIG: %+v", cfg)

	awsSession(*profile, cfg)

	awsUser(false)
	log.Debugf("USER: %+v", usr)

	switch {
	case *listMfa:
		printMfa()
	case *listRoles, *makeConf:
		roleHandler()
	case *updateFlag:
		if err := versionCheck(Version); err != nil {
			log.Debugf("Error checking version: %v", err)
		}
	case *diagFlag:
		if err := runDiagnostics(cfg); err != nil {
			log.Debugf("error running diagnostics: %v", err)
		}
	case *ec2MdFlag:
		log.Debug("Metadata Server")
		if usr.IdentityType == "user" {
			opts := new(metadata.EC2MetadataInput)
			opts.Config = cfg  // should never be nil, from resolveConfig() call above
			opts.Logger = log  // should never be nil, initialized at startup
			opts.Session = ses // should never be nil, from awsSession() above
			opts.User = usr    // should never be nil, from awsUser() above
			opts.InitialProfile = *profile
			opts.SessionCacheDir = filepath.Dir(sessionTokenCacheFile())

			if profile != nil && len(*profile) > 0 {
				cp := sessionTokenCredentials()
				if _, err := cp.Get(); err != nil {
					log.Fatal("Error getting initial credentials: %v", err)
				}
			}

			log.Fatal(metadata.NewEC2MetadataService(opts))
		}
	default:
		var c *credentials.Credentials

		if usr.IdentityType == "user" {
			c = handleUserCreds()
		} else {
			// non-IAM user (instance profile, other?)
			c = assumeRoleCredentials(ses)
		}

		signal.Notify(sigCh, os.Interrupt, syscall.SIGQUIT)
		go func() {
			for {
				sig := <-sigCh
				log.Debugf("Got signal: %s", sig.String())
			}
		}()

		switch p {
		case shell.FullCommand():
			h := ssm.NewSsmHandler(ses.Copy(ses.Config.WithCredentials(c))).WithLogger(log)
			if err := h.StartSession(*shellArgs.target); err != nil {
				log.Fatal(err)
			}
		case fwd.FullCommand():
			host, rp, err := net.SplitHostPort(*fwdArgs.target)
			if err != nil {
				log.Fatal(err)
			}
			lp := fmt.Sprintf("%d", *fwdArgs.localPort)

			h := ssm.NewSsmHandler(ses.Copy(ses.Config.WithCredentials(c))).WithLogger(log)
			if err := h.ForwardPort(host, lp, rp); err != nil {
				log.Fatal(err)
			}
		default:
			creds, err := c.Get()
			if err != nil {
				log.Fatalf("Error getting credentials: %v", err)
			}

			updateEnv(creds)

			cmd := execArgs.cmd

			if len(*cmd) > 0 {
				if !*envFlag {
					runEcsSvc(c)
				}

				cmd = wrapCmd(cmd)
				c := exec.Command((*cmd)[0], (*cmd)[1:]...)
				c.Stdin = os.Stdin
				c.Stdout = os.Stdout
				c.Stderr = os.Stderr

				err = c.Run()
				if err != nil {
					log.Debug("Error running command")
					log.Fatalf("%v", err)
				}
				os.Exit(0)
			} else {
				printCredentials()
			}
		}
	}
}

// return the 1st non-nil value with a length > 0, otherwise return nil
func coalesce(vals ...*string) *string {
	for _, v := range vals {
		if v != nil && len(*v) > 0 {
			return v
		}
	}
	return nil
}

// If AWS_PROFILE env var is set, use its value.  Otherwise, create a kingpin command arg to fetch it from the cmdline
func profileEnvArg(cmd *kingpin.CmdClause, desc string) *string {
	ev := os.Getenv(config.ProfileEnvVar)
	if len(ev) < 1 {
		return cmd.Arg("profile", desc).String()
	}
	return &ev
}

func runEcsSvc(c *credentials.Credentials) {
	s, err := metadata.NewEcsMetadataService(&metadata.EcsMetadataInput{Credentials: c, Logger: log})
	if err != nil {
		log.Fatal(err)
	}
	log.Debugf("http credential provider endpoint: %s", s.Url)

	for _, v := range []string{"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"} {
		os.Unsetenv(v)
	}

	// AWS_CREDENTIAL_PROFILES_FILE is a Java SDK specific env var for the credential file location
	for _, v := range []string{"AWS_SHARED_CREDENTIALS_FILE", "AWS_CREDENTIAL_PROFILES_FILE"} {
		os.Setenv(v, os.DevNull)
	}

	os.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", s.Url.String())

	go s.Run()
}

func wrapCmd(cmd *[]string) *[]string {
	// If on a non-windows platform, with the SHELL environment variable set, and a call to
	// exec.LookPath() for the command fails, run the command in a sub-shell so we can support shell aliases.
	newCmd := make([]string, 0)
	if cmd == nil || len(*cmd) < 1 {
		return &newCmd
	}

	if runtime.GOOS != "windows" {
		c, err := exec.LookPath((*cmd)[0])
		if len(c) < 1 || err != nil {
			sh := os.Getenv("SHELL")
			if strings.HasSuffix(sh, "/bash") || strings.HasSuffix(sh, "/fish") ||
				strings.HasSuffix(sh, "/zsh") || strings.HasSuffix(sh, "/ksh") {
				newCmd = append(newCmd, sh, "-i", "-c", strings.Join(*cmd, " "))
			}
			// Add other shells here as need arises
		}
	}

	if len(newCmd) == 0 {
		// We haven't wrapped provided command
		newCmd = append(newCmd, (*cmd)...)
	}

	if log != nil {
		log.Debugf("WRAPPED CMD: %v", newCmd)
	}

	return &newCmd
}

func printCredentials() {
	format := "%s %s='%s'\n"
	exportToken := "export"
	switch runtime.GOOS {
	case "windows":
		// SHELL env var is not set by default in "normal" Windows cmd.exe and PowerShell sessions.
		// If we detect it, assume we're running under something like git-bash (or maybe Cygwin?)
		// and fall through to using linux-style env var setting syntax
		if len(os.Getenv("SHELL")) < 1 {
			exportToken = "set"
			format = "%s %s=%s\n"
		}
	}

	envVars := []string{
		config.RegionEnvVar, config.DefaultRegionEnvVar,
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWSRUNAS_PROFILE",
	}

	for _, v := range envVars {
		val, ok := os.LookupEnv(v)
		if ok {
			fmt.Printf(format, exportToken, v, val)
		}
	}
}

func updateEnv(creds credentials.Value) {
	// Explicitly unset AWS_PROFILE to avoid unintended consequences
	os.Unsetenv(config.ProfileEnvVar)

	// Profile name was not a Role ARN, so let's pass that through as a new env var
	if *profile != cfg.RoleArn {
		os.Setenv("AWSRUNAS_PROFILE", *profile)
	}

	// Pass AWS_REGION through if it was set in our env, or found in config.
	// Ensure that called program gets the expected region.  Also set AWS_DEFAULT_REGION
	// so awscli works as expected, otherwise it will use any region from the profile
	if cfg != nil && len(cfg.Region) > 0 {
		os.Setenv(config.RegionEnvVar, cfg.Region)
		os.Setenv(config.DefaultRegionEnvVar, cfg.Region)
	}

	os.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)

	// If session token creds were returned, set them. Otherwise explicitly unset them
	// to keep the sdk from getting confused.  AFAIK, we should always have SessionTokens,
	// since our entire process revolves around them. But always code defensively
	if len(creds.SessionToken) > 0 {
		os.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
		os.Setenv("AWS_SECURITY_TOKEN", creds.SessionToken)
	} else {
		os.Unsetenv("AWS_SESSION_TOKEN")
		os.Unsetenv("AWS_SECURITY_TOKEN")
	}
}

func handleUserCreds() *credentials.Credentials {
	var c *credentials.Credentials

	checkRefresh()

	if cfg.RoleDuration > 1*time.Hour && len(cfg.RoleArn) > 0 {
		// Not allowed to use session tokens to fetch assume role credentials > 1h
		c = assumeRoleCredentials(ses)
	} else {
		sc := sessionTokenCredentials()
		s := ses.Copy(new(aws.Config).WithCredentials(sc))

		if !*sesCreds && len(cfg.RoleArn) > 0 {
			cfg.MfaSerial = "" // unset MfaSerial since MFA is handled in the session token
			c = assumeRoleCredentials(s)
		} else {
			// -s option found, or no role arn provided/found
			c = sc
		}
	}

	if *showExpire {
		printCredExpire()
	}

	return c
}

func checkRefresh() {
	if *refresh {
		var err error
		if !*sesCreds {
			err = os.Remove(assumeRoleCacheFile())
		}
		err = os.Remove(sessionTokenCacheFile())
		if err != nil {
			log.Debugf("Error removing cache files: %v", err)
		}
	}
}

func printCredExpire() {
	var f *cache.FileCredentialCache

	if !*sesCreds && len(cfg.RoleArn) > 0 {
		f = &cache.FileCredentialCache{Path: assumeRoleCacheFile()}
	} else {
		f = &cache.FileCredentialCache{Path: sessionTokenCacheFile()}
	}

	creds, err := f.Fetch()
	if err != nil {
		creds = new(cache.CacheableCredentials)
	}

	exp := time.Unix(creds.Expiration, 0)
	format := exp.Format("2006-01-02 15:04:05")
	hmn := humanize.Time(exp)

	tense := "will expire"
	if exp.Before(time.Now()) {
		tense = "expired"
	}

	if _, err := fmt.Fprintf(os.Stderr, "Credentials %s on %s (%s)\n", tense, format, hmn); err != nil {
		log.Errorf("Error printing credentials: %v", err)
	}
}

func cacheFile(f string) string {
	d := filepath.Dir(defaults.SharedCredentialsFilename())
	return filepath.Join(d, f)
}

func assumeRoleCacheFile() string {
	p := *profile
	if *profile == cfg.RoleArn {
		a, _ := arn.Parse(*profile) // if we get this far, it's assumed the ARN will parse
		r := strings.Split(a.Resource, "/")
		p = fmt.Sprintf("%s-%s", a.AccountID, r[len(r)-1])
	}

	cf := fmt.Sprintf("%s_%s", assumeRoleCachePrefix, p)
	if log != nil {
		log.Debugf("AssumeRole CACHE PATH: %s", cf)
	}
	return cacheFile(cf)
}

func sessionTokenCacheFile() string {
	p := cfg.SourceProfile
	if len(p) < 1 {
		if len(*profile) > 0 {
			p = *profile
		} else {
			p = "default"
		}
	}

	cf := fmt.Sprintf("%s_%s", sessionTokenCachePrefix, p)
	if log != nil {
		log.Debugf("SessionToken CACHE PATH: %s", cf)
	}
	return cacheFile(cf)
}

func assumeRoleCredentials(c client.ConfigProvider) *credentials.Credentials {
	var ew time.Duration

	if c == nil {
		c = ses
	}

	if cfg.RoleDuration < credlib.AssumeRoleMinDuration {
		ew = credlib.AssumeRoleMinDuration / 10
	} else {
		ew = cfg.RoleDuration / 10
	}

	return credlib.NewAssumeRoleCredentials(c, cfg.RoleArn, func(p *credlib.AssumeRoleProvider) {
		p.RoleSessionName = usr.UserName
		p.ExternalID = cfg.ExternalID
		p.SerialNumber = cfg.MfaSerial
		p.Duration = cfg.RoleDuration
		p.ExpiryWindow = ew
		p.Cache = &cache.FileCredentialCache{Path: assumeRoleCacheFile()}
		p.WithLogger(log)

		if mfaCode != nil && len(*mfaCode) > 0 {
			p.TokenCode = *mfaCode
		} else {
			p.TokenProvider = credlib.StdinTokenProvider
		}
	})
}

func sessionTokenCredentials(cacheFile ...string) *credentials.Credentials {
	var ew time.Duration

	if len(cacheFile) < 1 || len(cacheFile[0]) < 1 {
		cacheFile = []string{sessionTokenCacheFile()}
	}

	if cfg.RoleDuration < credlib.SessionTokenMinDuration {
		ew = credlib.SessionTokenMinDuration / 10
	} else {
		ew = cfg.SessionDuration / 10
	}

	return credlib.NewSessionCredentials(ses, func(p *credlib.SessionTokenProvider) {
		p.Cache = &cache.FileCredentialCache{Path: cacheFile[0]}
		p.SerialNumber = cfg.MfaSerial
		p.Duration = cfg.SessionDuration
		p.ExpiryWindow = ew
		p.WithLogger(log)

		if mfaCode != nil && len(*mfaCode) > 0 {
			p.TokenCode = *mfaCode
		} else {
			p.TokenProvider = credlib.StdinTokenProvider
		}
	})
}

func roleHandler() {
	if usr.IdentityType == "user" {
		rg := util.NewAwsRoleGetter(ses, usr.UserName).WithLogger(log)
		roles := rg.Roles()

		if *listRoles {
			log.Debug("List Roles")
			fmt.Printf("Available role ARNs for %s (%s)\n", usr.UserName, *usr.Identity.Arn)
			for _, v := range roles {
				fmt.Printf("  %s\n", v)
			}
		}

		if *makeConf {
			log.Debug("Make Configuration Files.")
			log.Warnf("This feature is not yet implemented")
			// todo
			//var mfa *string
			//if mfaArn != nil && len(*mfaArn) > 0 {
			//	// MFA arn provided by cmdline option
			//	mfa = mfaArn
			//} else {
			//	m, err := util.LookupMfa(ses)
			//	if err != nil {
			//		log.Errorf("MFA lookup failed, will not configure MFA: %v", err)
			//	}
			//
			//	if len(m) > 0 {
			//		// use 1st MFA device found
			//		mfa = m[0].SerialNumber
			//	}
			//}
		}
	}
}

func printMfa() {
	log.Debug("List MFA")
	if usr.IdentityType == "user" {
		mfa, err := lookupMfa()
		if err != nil {
			log.Fatalf("Error retrieving MFA info: %v", err)
		}

		for _, d := range mfa {
			fmt.Printf("%s\n", *d.SerialNumber)
		}
	}
}

func lookupMfa() ([]*iam.MFADevice, error) {
	s := iam.New(ses)

	res, err := s.ListMFADevices(&iam.ListMFADevicesInput{})
	if err != nil {
		return nil, err
	}

	return res.MFADevices, nil
}

func resolveConfig() {
	usrCfg := config.AwsConfig{MfaSerial: *mfaArn, SessionDuration: *duration, RoleDuration: *roleDuration}
	r, err := config.NewConfigResolver(&usrCfg)
	if err != nil {
		log.Error(err)
		log.Fatal("The error message above means the expected config file is missing or malformed")
	}
	r.WithLogger(log)

	cfg, err = r.ResolveConfig(*profile)
	if err != nil {
		log.Fatalf("ResolveConfig: %v", err)
	}
}

func awsSession(profile string, cfg *config.AwsConfig) {
	var p string

	sc := new(aws.Config).WithLogger(log).WithCredentialsChainVerboseErrors(true).WithRegion(cfg.Region)
	if *verbose {
		sc.LogLevel = aws.LogLevel(aws.LogDebug)
	}
	opts := session.Options{Config: *sc}

	// profile was not a role ARN (implies that it's a profile in the config file)
	if profile != cfg.RoleArn {
		p = profile
	} else {
		// profile appears to be an ARN, and may have been set as the AWS_PROFILE env var.  Unset that to allow
		// the SDK session to properly resolve credentials
		os.Unsetenv(config.ProfileEnvVar)
	}

	if len(cfg.SourceProfile) > 0 {
		p = cfg.SourceProfile
	}
	opts.Profile = p

	// Do not set opts.SharedConfigState to enabled so we only get credentials for the profile.  We don't want the config
	// file values getting in the way (like prompting for MFA and assuming roles) at this point.
	ses = session.Must(session.NewSessionWithOptions(opts))
}

func awsUser(resetEnv bool) {
	var err error

	if resetEnv {
		os.Unsetenv("AWS_ACCESS_KEY_ID")
		os.Unsetenv("AWS_ACCESS_KEY")
		os.Unsetenv("AWS_SECRET_ACCESS_KEY")
		os.Unsetenv("AWS_SECRET_KEY")
		os.Unsetenv("AWS_SECURITY_TOKEN")
		os.Unsetenv("AWS_SESSION_TOKEN")
		os.Unsetenv(config.ProfileEnvVar)
		awsSession(*profile, cfg)
	}

	usr, err = credlib.NewAwsIdentityManager(ses).WithLogger(log).GetCallerIdentity()
	if err != nil {
		if resetEnv {
			log.Fatalf("Error getting IAM user info: %v", err)
		}

		log.Warn("Error getting IAM user info, retrying with AWS credential env vars unset")
		awsUser(true)
	}
}
