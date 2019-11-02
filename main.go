package main

import (
	"aws-runas/lib/cache"
	"aws-runas/lib/config"
	"aws-runas/lib/identity"
	"aws-runas/lib/saml"
	"fmt"
	"github.com/alecthomas/kingpin"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	cfglib "github.com/mmmorris1975/aws-config/config"
	"github.com/mmmorris1975/simple-logger/logger"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var (
	profile    *string
	cfg        *config.AwsConfig
	ses        *session.Session
	samlClient saml.AwsSamlClient
	idp        identity.Provider
	usr        *identity.Identity

	log        = logger.StdLogger
	cookieFile = filepath.Join(filepath.Dir(defaults.SharedConfigFilename()), ".saml-client.cookies")
)

func main() {
	kingpin.Parse()
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
	case *ec2MdFlag:
	default:

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
	log.Debug("ENV Config: %+v", env)

	// user-supplied config
	usrCfg := &cfglib.AwsConfig{
		ExternalId: *extnId,
		MfaSerial:  *mfaArn,
		Profile:    *profile,
	}
	log.Debug("USER Config: %+v", usrCfg)

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
	log.Debug("PROFILE Config: %+v", resolvedProfile)

	mergedCfg, err := res.Merge(resolvedProfile, env, usrCfg)
	if err != nil {
		return err
	}
	log.Debug("MERGED Config: %+v", mergedCfg)

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

	log.Debug("FINAL Config: %+v", newCfg)
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
		s.Username = *samlUser
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
