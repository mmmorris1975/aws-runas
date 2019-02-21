package main

import (
	"fmt"
	"github.com/mmmorris1975/aws-runas/lib/config"
	"os"
	"strings"
)

// RunDiagnostics will sanity check various configuration items
func runDiagnostics(c *config.AwsConfig) error {
	if log != nil {
		log.Debugf("Diagnostics")
	}

	// fixme - this really isn't valid, since role could be provided via cmdline arg or env var, so there is no source profile
	//if len(cfg.RoleArn) > 0 && len(cfg.SourceProfile) < 1 {
	//	log.Fatalf("source_profile attribute is required when role_arn is set for profile %s", *profile)
	//}

	envAk := os.Getenv("AWS_ACCESS_KEY_ID")
	envSt := os.Getenv("AWS_SESSION_TOKEN")

	if len(envAk) > 0 && len(envSt) > 0 {
		if strings.HasPrefix(envAk, "AKIA") {
			return fmt.Errorf("detected static access key env var along with session token env var, this is invalid")
		}
	}

	//fmt.Printf("PROFILE: %s\n", p.Name)
	fmt.Printf("ROLE ARN: %s\n", c.RoleArn)
	fmt.Printf("MFA SERIAL: %s\n", c.MfaSerial)
	fmt.Printf("EXTERNAL ID: %s\n", c.ExternalID)
	//fmt.Printf("ROLE SESSION NAME: %s\n", c.RoleSessionName)
	fmt.Printf("SESSION TOKEN DURATION: %s\n", c.SessionDuration)
	fmt.Printf("ASSUME ROLE CREDENTIAL DURATION: %s\n", c.RoleDuration)
	fmt.Printf("REGION: %s\n", c.Region)
	fmt.Printf("SOURCE PROFILE: %s\n", c.SourceProfile)

	// fixme
	//c := AwsCredentialsFile()
	//f, err := ini.Load(c)
	//if err != nil {
	//	return err
	//}
	//f.BlockMode = false
	//
	//profile := c.SourceProfile
	//if len(profile) < 1 {
	//	profile = p.Name
	//}
	//
	//s, err := f.GetSection(profile)
	//if err != nil {
	//	// if access key envvar exists, assume creds are configured as envvars and not in credentials file
	//	// otherwise, flag as an error, since creds are totally missing
	//	if len(envAk) < 1 {
	//		return fmt.Errorf("missing [%s] section in credentials file %s", profile, c)
	//	}
	//
	//}
	//
	//if s.HasKey("aws_access_key_id") && s.HasKey("aws_secret_access_key") {
	//	if len(envAk) > 0 || len(envSt) > 0 {
	//		return fmt.Errorf("detected AWS credential environment variables and profile credentials, this may confuse aws-runas")
	//	}
	//} else {
	//	// section is in cred file, but one or both of the cred keys are missing
	//	if len(envAk) < 1 {
	//		return fmt.Errorf("profile found in credentials file, but missing credential configuration")
	//	}
	//}

	return nil
}
