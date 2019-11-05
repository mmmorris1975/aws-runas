package main

import (
	"aws-runas/lib/cache"
	"aws-runas/lib/config"
	credlib "aws-runas/lib/credentials"
	"aws-runas/lib/identity"
	"aws-runas/lib/metadata"
	"aws-runas/lib/saml"
	"aws-runas/lib/ssm"
	"fmt"
	"github.com/alecthomas/kingpin"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/dustin/go-humanize"
	cfglib "github.com/mmmorris1975/aws-config/config"
	"github.com/mmmorris1975/simple-logger/logger"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	assumeRoleCachePrefix   = ".aws_assume_role"
	sessionTokenCachePrefix = ".aws_session_token"
	jumpRoleCachePrefix     = ".aws_saml_role"
)

var (
	profile    *string
	cfg        *config.AwsConfig
	ses        *session.Session
	samlClient saml.AwsSamlClient
	idp        identity.Provider
	usr        *identity.Identity

	log        = logger.StdLogger
	sigCh      = make(chan os.Signal, 3)
	cookieFile = filepath.Join(filepath.Dir(defaults.SharedConfigFilename()), ".saml-client.cookies")
)

func main() {
	p := kingpin.Parse()
	profile = coalesce(execArgs.profile, shellArgs.profile, fwdArgs.profile, aws.String("default"))

	if *verbose {
		log.SetLevel(logger.DEBUG)
	}

	if err := resolveConfig(); err != nil {
		log.Fatal(err)
	}

	awsSession()

	if err := awsUser(); err != nil {
		log.Fatal(err)
	}
	log.Debugf("USER: %+v", usr)

	switch {
	case *listMfa:
		printMfa(iam.New(ses))
	case *listRoles:
		printRoles()
	case *updateFlag:
		if err := versionCheck(Version); err != nil {
			log.Fatal(err)
		}
	case *diagFlag:
		if err := runDiagnostics(cfg); err != nil {
			log.Debugf("error running diagnostics: %v", err)
		}
	case *ec2MdFlag:
		log.Debug("Metadata Server")
		if usr.IdentityType == "user" {
			opts := &metadata.EC2MetadataInput{
				Config:          cfg,
				InitialProfile:  cfg.Profile,
				Logger:          log,
				Session:         ses,
				SessionCacheDir: filepath.Dir(sessionCredCacheName()),
				User:            usr,
			}

			log.Fatal(metadata.NewEC2MetadataService(opts))
		}
	default:
		var c *credentials.Credentials

		if usr.IdentityType == "user" {
			checkRefresh()

			if usr.Provider == saml.IdentityProviderSaml {
				var err error
				c, err = handleSamlUserCredentials()
				if err != nil {
					log.Fatal(err)
				}
			} else {
				c = handleAwsUserCredentials()
			}

			if *showExpire {
				printCredExpire(c)
			}
		} else {
			// possibly on EC2 ... do AssumeRole directly
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
			h := ssm.NewSsmHandler(ses.Copy(new(aws.Config).WithCredentials(c).WithLogger(log)))
			if err := h.StartSession(*shellArgs.target); err != nil {
				log.Fatal(err)
			}
		case fwd.FullCommand():
			host, remPort, err := net.SplitHostPort(*fwdArgs.target)
			if err != nil {
				log.Fatal(err)
			}

			locPort := fmt.Sprintf("%d", *fwdArgs.localPort)

			h := ssm.NewSsmHandler(ses.Copy(new(aws.Config).WithCredentials(c).WithLogger(log)))
			if err := h.ForwardPort(host, locPort, remPort); err != nil {
				log.Fatal(err)
			}
		default:
			creds, err := c.Get()
			if err != nil {
				log.Fatalf("Error getting credentials: %v", err)
			}

			updateEnv(creds)
			cmd := *execArgs.cmd

			if len(cmd) > 0 {
				if !*envFlag {
					runEcsSvc(c)
				}

				wrapped := wrapCmd(cmd)
				c := exec.Command(wrapped[0], wrapped[1:]...)
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

func updateEnv(creds credentials.Value) {
	// Explicitly unset AWS_PROFILE to avoid unintended consequences
	os.Unsetenv(cfglib.ProfileEnvVar)

	// Profile name was not a Role ARN, so let's pass that through as a new env var
	if *profile != cfg.RoleArn {
		os.Setenv("AWSRUNAS_PROFILE", *profile)
	}

	// Pass AWS_REGION through if it was set in our env, or found in config.
	// Ensure that called program gets the expected region.  Also set AWS_DEFAULT_REGION
	// so awscli works as expected, otherwise it will use any region from the profile
	if cfg != nil && len(cfg.Region) > 0 {
		os.Setenv("AWS_REGION", cfg.Region)
		os.Setenv("AWS_DEFAULT_REGION", cfg.Region)
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
		"AWS_REGION", "AWS_DEFAULT_REGION",
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

func runEcsSvc(c *credentials.Credentials) {
	// modify the execution environment to force use of ECS credential URL
	unsetEnv := []string{"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"}
	for _, e := range unsetEnv {
		os.Unsetenv(e)
	}

	// AWS_CREDENTIAL_PROFILES_FILE is a Java SDK specific env var for the credential file location
	for _, v := range []string{"AWS_SHARED_CREDENTIALS_FILE", "AWS_CREDENTIAL_PROFILES_FILE"} {
		os.Setenv(v, os.DevNull)
	}

	in := &metadata.EcsMetadataInput{Credentials: c, Logger: log}
	s, err := metadata.NewEcsMetadataService(in)
	if err != nil {
		log.Fatal(err)
	}

	os.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", s.Url.String())
	go s.Run()
}

func wrapCmd(cmd []string) []string {
	// If on a non-windows platform, with the SHELL environment variable set, and a call to
	// exec.LookPath() for the command fails, run the command in a sub-shell so we can support shell aliases.
	newCmd := make([]string, 0)
	if len(cmd) < 1 {
		return newCmd
	}

	if runtime.GOOS != "windows" {
		c, err := exec.LookPath(cmd[0])
		if len(c) < 1 || err != nil {
			sh := os.Getenv("SHELL")
			if strings.HasSuffix(sh, "/bash") || strings.HasSuffix(sh, "/fish") ||
				strings.HasSuffix(sh, "/zsh") || strings.HasSuffix(sh, "/ksh") {
				newCmd = append(newCmd, sh, "-i", "-c", strings.Join(cmd, " "))
			}
			// Add other shells here as need arises
		}
	}

	if len(newCmd) == 0 {
		// We haven't wrapped provided command
		newCmd = append(newCmd, cmd...)
	}

	if log != nil {
		log.Debugf("WRAPPED CMD: %v", newCmd)
	}

	return newCmd
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

func resolveConfig() error {
	var resolvedProfile *cfglib.AwsConfig

	// INI file config resolver
	res, err := cfglib.NewAwsConfigResolver(nil)
	if err != nil {
		return err
	}

	// Env Var config resolver
	env, err := cfglib.NewEnvConfigProvider().Config()
	if err != nil {
		return err
	}
	log.Debugf("ENV Config: %+v", env)

	// user-supplied config
	usrCfg := &cfglib.AwsConfig{
		ExternalId: *extnId,
		MfaSerial:  *mfaArn,
		Profile:    *profile,
	}

	if _, err := arn.Parse(*profile); err == nil {
		// profile is a well-formed ARN, so it won't be in the config file, set it in our usrCfg
		usrCfg.RoleArn = *profile
		resolvedProfile, err = res.Resolve("") // grab default profile
		if err != nil {
			return err
		}
	} else {
		resolvedProfile, err = res.Resolve(*profile)
		if err != nil {
			return err
		}
	}
	log.Debugf("USER Config: %+v", usrCfg)
	log.Debugf("PROFILE Config: %+v", resolvedProfile)

	mergedCfg, err := res.Merge(resolvedProfile, env)
	if err != nil {
		return err
	}

	if len(usrCfg.ExternalId) > 0 {
		mergedCfg.ExternalId = usrCfg.ExternalId
	}

	if len(usrCfg.MfaSerial) > 0 {
		mergedCfg.MfaSerial = usrCfg.ExternalId
	}

	if len(usrCfg.Profile) > 0 {
		mergedCfg.Profile = usrCfg.Profile
	}

	if len(usrCfg.RoleArn) > 0 {
		mergedCfg.RoleArn = usrCfg.RoleArn
	}
	log.Debugf("MERGED Config: %+v", mergedCfg)

	cfg, err = finalConfig(mergedCfg)
	return err
}

func finalConfig(cfg *cfglib.AwsConfig) (*config.AwsConfig, error) {
	newCfg, err := config.Wrap(cfg)
	if err != nil {
		return nil, err
	}

	if jumpArn != nil && len(*jumpArn) > 0 {
		a, err := arn.Parse(*jumpArn)
		if err != nil {
			return nil, err
		}
		newCfg.JumpRoleArn = a
	}

	if duration != nil && *duration > 0 {
		newCfg.SessionTokenDuration = *duration
	}

	if roleDuration != nil && *roleDuration > 0 {
		newCfg.CredentialsDuration = *roleDuration
		newCfg.DurationSeconds = int((*roleDuration).Seconds())
	}

	if samlUrl != nil && *samlUrl != nil && len((*samlUrl).String()) > 0 {
		newCfg.SamlMetadataUrl = *samlUrl
	}

	if samlUser != nil && len(*samlUser) > 0 {
		newCfg.SamlUsername = *samlUser
	}

	log.Debugf("FINAL Config: %+v", newCfg)
	return newCfg, nil
}

func awsSession() {
	var p string

	sc := new(aws.Config).WithRegion(cfg.Region).WithCredentialsChainVerboseErrors(true).WithLogger(log)
	if *verbose {
		sc.LogLevel = aws.LogLevel(aws.LogDebug)
	}

	// profile was not a role ARN (implies that it's a profile in the config file)
	if *profile != cfg.RoleArn {
		p = *profile
	} else {
		// profile appears to be an ARN, and may have been set as the AWS_PROFILE env var.  Unset that to allow
		// the SDK session to properly resolve credentials
		os.Unsetenv(cfglib.ProfileEnvVar)
	}

	if len(cfg.SourceProfile) > 0 {
		p = cfg.SourceProfile
	}
	opts := session.Options{Config: *sc, Profile: p}

	// Do not set opts.SharedConfigState to enabled so we only get credentials for the profile.  We don't want the config
	// file values getting in the way (like prompting for MFA and assuming roles) at this point.
	ses = session.Must(session.NewSessionWithOptions(opts))
}

func awsUser() error {
	var err error

	// default to AWS IAM identity, switch to SAML identity if SamlMetadataUrl config attribute is set
	idp = identity.NewAwsIdentityProvider(ses)
	if cfg.SamlMetadataUrl != nil && len(cfg.SamlMetadataUrl.String()) > 0 {
		log.Debug("Using SAML Identity")
		samlClient, err = samlClientWithReauth()
		if err != nil {
			return err
		}
		idp = samlClient
	}

	usr, err = idp.GetIdentity()
	if err != nil {
		// in v1, if identity lookup failed, we'd retry after unsetting the credential and profile env vars and
		// re-initializing the ses variable via awsSession().  Keep that behavior in v2?
		//if _, ok := idp.(*identity.AwsIdentityProvider); ok {
		//
		//}
		return err
	}
	return nil
}

func samlClientWithReauth() (saml.AwsSamlClient, error) {
	jar, err := cache.NewCookieJarFile(cookieFile)
	if err != nil {
		return nil, err
	}

	c, err := saml.GetClient(cfg.SamlMetadataUrl.String(), func(s *saml.SamlClient) {
		s.Username = cfg.SamlUsername
		s.Password = *samlPass
		s.MfaToken = *mfaCode
		s.SetCookieJar(jar)
	})
	if err != nil {
		return nil, err
	}

	// If our cookies are still valid, the first AwsSaml() call should succeed.
	// Assume any failure necessitates a re-auth.  Retry AwsSaml() to validate
	if _, err := c.AwsSaml(); err != nil {
		if err := c.Authenticate(); err != nil {
			return nil, err
		}

		if _, err := c.AwsSaml(); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func printMfa(c iamiface.IAMAPI) {
	// By passing in the iamiface.IAMAPI interface type we can make this function testable with a mock IAM client
	//
	// MFA retrieval only supported for AWS IAM users (not roles).  If a non-nil samlClient is detected
	// we assume that SAML is being used instead of IAM, so we'll bail
	if usr.IdentityType == "user" && samlClient == nil {
		res, err := c.ListMFADevices(new(iam.ListMFADevicesInput))
		if err != nil {
			log.Fatal(err)
		}

		for _, d := range res.MFADevices {
			fmt.Println(*d.SerialNumber)
		}
	}
}

func printRoles() {
	roles, err := idp.Roles()
	if err != nil {
		log.Fatal(err)
	}
	sort.Strings(roles)

	fmt.Printf("Available role ARNs for %s\n", usr.Username)
	for _, r := range roles {
		// filter out wildcards roles, since they can't be used in config files
		if strings.Contains(r, "*") {
			continue
		}
		fmt.Println("  " + r)
	}
}

func handleSamlUserCredentials() (*credentials.Credentials, error) {
	var c *credentials.Credentials

	if samlClient == nil {
		return c, fmt.Errorf("invalid saml client")
	}

	samlDoc, err := samlClient.AwsSaml()
	if err != nil {
		return c, err
	}

	d, err := samlClient.GetSessionDuration()
	if err != nil {
		return c, err
	}

	sc := credlib.NewSamlRoleCredentials(ses, cfg.RoleArn, samlDoc, func(p *credlib.SamlRoleProvider) {
		p.Log = log
		p.RoleSessionName = usr.Username
		p.Duration = time.Duration(d) * time.Second
		p.ExpiryWindow = time.Duration(d) * time.Second / 10
		p.Cache = cache.NewFileCredentialCache(roleCredCacheName())

		if len(cfg.JumpRoleArn.Resource) > 0 {
			p.RoleARN = cfg.JumpRoleArn.String()
			p.Cache = cache.NewFileCredentialCache(jumpRoleCredCacheName())
		}
	})

	if len(cfg.JumpRoleArn.Resource) > 0 {
		cfg.MfaSerial = "" // explicitly unset MfaSerial since MFA is handled by SAML
		s := ses.Copy(new(aws.Config).WithCredentials(sc))

		c = assumeRoleCredentials(s)
	} else {
		c = sc
	}

	return c, nil
}

func handleAwsUserCredentials() *credentials.Credentials {
	var c *credentials.Credentials

	if cfg.CredentialsDuration > 1*time.Hour && len(cfg.RoleArn) > 0 {
		c = assumeRoleCredentials(ses)
	} else {
		sc := sessionTokenCredentials(ses)

		if !*sesCreds && len(cfg.RoleArn) > 0 {
			cfg.MfaSerial = "" // explicitly unset MfaSerial since MFA is handled in the session credentials
			s := ses.Copy(new(aws.Config).WithCredentials(sc))

			c = assumeRoleCredentials(s)
		} else {
			c = sc
		}
	}

	return c
}

func sessionTokenCredentials(c client.ConfigProvider) *credentials.Credentials {
	if c == nil {
		c = ses
	}

	ew := cfg.SessionTokenDuration / 10
	if cfg.SessionTokenDuration < credlib.SessionTokenMinDuration {
		ew = credlib.SessionTokenMinDuration / 10
	}

	return credlib.NewSessionTokenCredentials(c, func(p *credlib.SessionTokenProvider) {
		p.Cache = cache.NewFileCredentialCache(sessionCredCacheName())
		p.Duration = cfg.SessionTokenDuration
		p.ExpiryWindow = ew
		p.Log = log
		p.SerialNumber = cfg.MfaSerial
		p.TokenCode = *mfaCode
		p.TokenProvider = credlib.StdinMfaTokenProvider
	})
}

func assumeRoleCredentials(c client.ConfigProvider) *credentials.Credentials {
	if c == nil {
		c = ses
	}

	ew := cfg.CredentialsDuration / 10
	if cfg.CredentialsDuration < credlib.AssumeRoleMinDuration {
		ew = credlib.AssumeRoleMinDuration / 10
	}

	return credlib.NewAssumeRoleCredentials(c, cfg.RoleArn, func(p *credlib.AssumeRoleProvider) {
		p.Cache = cache.NewFileCredentialCache(roleCredCacheName())
		p.Duration = cfg.CredentialsDuration
		p.ExternalID = cfg.ExternalId
		p.ExpiryWindow = ew
		p.Log = log
		p.RoleSessionName = usr.Username
		p.SerialNumber = cfg.MfaSerial
		p.TokenCode = *mfaCode
		p.TokenProvider = credlib.StdinMfaTokenProvider
	})
}

func sessionCredCacheName() string {
	f := os.DevNull

	p := cfg.SourceProfile
	if len(p) < 1 {
		if len(*profile) > 0 {
			p = *profile
		} else {
			p = "default"
		}
	}

	f = cacheFile(fmt.Sprintf("%s_%s", sessionTokenCachePrefix, p))
	log.Debugf("SessionToken CACHE PATH: %s", f)
	return f
}

func roleCredCacheName() string {
	f := os.DevNull

	p := *profile
	if *profile == cfg.RoleArn {
		a, _ := arn.Parse(*profile) // if we get this far, it's assumed the ARN will parse
		r := strings.Split(a.Resource, "/")
		p = fmt.Sprintf("%s-%s", a.AccountID, r[len(r)-1])
	}

	f = cacheFile(fmt.Sprintf("%s_%s", assumeRoleCachePrefix, p))
	log.Debugf("AssumeRole CACHE PATH: %s", f)
	return f
}

func jumpRoleCredCacheName() string {
	f := os.DevNull

	r := strings.Split(cfg.JumpRoleArn.Resource, "/")
	p := fmt.Sprintf("%s-%s", cfg.JumpRoleArn.AccountID, r[len(r)-1])

	f = cacheFile(fmt.Sprintf("%s_%s", jumpRoleCachePrefix, p))
	log.Debugf("SAML JumpRole CACHE PATH: %s", f)
	return f
}

func cacheFile(f string) string {
	d := filepath.Dir(defaults.SharedCredentialsFilename())
	return filepath.Join(d, f)
}

// providers require that the credentials are loaded before the ExpiresAt() call will do anything meaningful, so we'll
// call Get() here and load (or re-fetch) the credentials.  This should mean that someone will never see a message about
// their credentials being expired, since the call to Get() would force a refresh if they are actually expired or invalid.
func printCredExpire(c *credentials.Credentials) {
	_, err := c.Get()
	if err != nil {
		log.Errorf("error loading credentials: %v", err)
		return
	}

	t, err := c.ExpiresAt()
	if err != nil {
		log.Errorf("error checking credential expiration: %v", err)
		return
	}

	format := t.Format("2006-01-02 15:04:05")
	hmn := humanize.Time(t)

	tense := "will expire"
	if t.Before(time.Now()) {
		tense = "expired"
	}

	if _, err := fmt.Fprintf(os.Stderr, "Credentials %s on %s (%s)\n", tense, format, hmn); err != nil {
		log.Errorf("Error printing credentials: %v", err)
	}
}

// this gets a little weird when dealing with saml credentials, since we're initializing the provider very early
// (as part of awsUser()), it means that deleting the cookie file doesn't do much until the next time we run the tool.
// Additionally, the cookie file may contain multiple saml provider cookies, so we could dork up other profiles by
// whacking the entire file.  Not going to over think things yet, until someone comes up with a requirement to do so.
func checkRefresh() {
	if *refresh {
		if usr.Provider == saml.IdentityProviderSaml {
			//if err := os.Remove(cookieFile); err != nil {
			//	if !os.IsNotExist(err) {
			//		log.Errorf("error removing cookie jar: %v", err)
			//	}
			//}

			if err := os.Remove(jumpRoleCredCacheName()); err != nil {
				if !os.IsNotExist(err) {
					log.Errorf("error removing jump role cred cache: %v", err)
				}
			}
		} else {
			log.Infof("deleting session creds")
			if err := os.Remove(sessionCredCacheName()); err != nil {
				if !os.IsNotExist(err) {
					log.Errorf("error removing session cred cache: %v", err)
				}
			}
		}

		if err := os.Remove(roleCredCacheName()); err != nil {
			if !os.IsNotExist(err) {
				log.Errorf("error removing role cred cache: %v", err)
			}
		}
	}
}
