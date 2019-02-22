package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	cfglib "github.com/mmmorris1975/aws-config/config"
	"github.com/mmmorris1975/aws-runas/lib/config"
	"os"
	"strings"
)

// RunDiagnostics will sanity check various configuration items, print errors as we find them
func runDiagnostics(c *config.AwsConfig) error {
	log.Debugf("Diagnostics")

	envAk := os.Getenv("AWS_ACCESS_KEY_ID")
	envSt := os.Getenv("AWS_SESSION_TOKEN")

	if len(envAk) > 0 && len(envSt) > 0 {
		if strings.HasPrefix(envAk, "AKIA") {
			log.Errorf("detected static access key env var along with session token env var, this is invalid")
		}
	}

	// Check that region is set
	if len(c.Region) < 1 {
		log.Errorf("region is not set, it must be specified in the config file or as an environment var")
	}

	if len(*profile) < 1 {
		log.Warn("No profile specified, will only check default section. Provide a profile name for more validation")
		profile = aws.String("default")
	}

	if *profile == c.RoleArn {
		// profile was a Role ARN, config will be whatever was explicitly passed + env var config,
		// and possibly a default config, if the config file exists and has the default section
		log.Infof("Role ARN provided as the profile, configuration file will not be checked")
	} else {
		// profile is a config profile name
		if len(*profile) > 0 {
			var cfgCreds bool

			if len(c.RoleArn) > 0 {
				// provided profile uses a role, so it must have a valid source_profile attribute
				if len(c.SourceProfile) < 1 {
					log.Errorf("missing source_profile configuration for profile '%s'", *profile)
				} else {
					// source_profile name must exist in the credentials file
					cfgCreds = checkCredentialProfile(c.SourceProfile)
				}
			} else {
				// not a profile with a role, must have matching section in creds file
				cfgCreds = checkCredentialProfile(*profile)
			}

			// check for profile creds and env var creds at the same time
			if cfgCreds && len(envAk) > 0 {
				log.Errorf("detected AWS credential environment variables and profile credentials, this may confuse aws-runas")
			}
		}
	}

	fmt.Printf("PROFILE: %s\n", *profile)
	fmt.Printf("REGION: %s\n", c.Region)
	fmt.Printf("SOURCE PROFILE: %s\n", c.SourceProfile)
	fmt.Printf("SESSION TOKEN DURATION: %s\n", c.SessionDuration)
	fmt.Printf("MFA SERIAL: %s\n", c.MfaSerial)
	fmt.Printf("ROLE ARN: %s\n", c.RoleArn)
	fmt.Printf("EXTERNAL ID: %s\n", c.ExternalID)
	fmt.Printf("ASSUME ROLE CREDENTIAL DURATION: %s\n", c.RoleDuration)

	return nil
}

func checkCredentialProfile(profile string) bool {
	cfg, err := cfglib.NewAwsCredentialsFile(nil)
	if err != nil {
		log.Errorf("error loading credentials file: %v", err)
		return false
	}

	p, err := cfg.Profile(profile)
	if err != nil {
		log.Errorf("error loading profile credentials: %v", err)
		return false
	}

	if !p.HasKey("aws_access_key_id") || !p.HasKey("aws_secret_access_key") {
		log.Errorf("incomplete or missing credentials for profile '%s'", profile)
		return false
	}

	return true
}
