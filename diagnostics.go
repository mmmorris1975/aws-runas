package main

import (
	"fmt"
	cfglib "github.com/mmmorris1975/aws-config/config"
	"github.com/mmmorris1975/aws-runas/lib/config"
	"os"
	"strings"
)

// RunDiagnostics will sanity check various configuration items, print errors as we find them
func runDiagnostics(c *config.AwsConfig) error {
	log.Debugf("Diagnostics")

	checkEnv()
	checkRegion(c)
	p := checkProfile(*profile)

	if p == c.RoleArn {
		// profile was a Role ARN, config will be whatever was explicitly passed + env var config,
		// and possibly a default config, if the config file exists and has the default section
		log.Infof("Role ARN provided as the profile, configuration file will not be checked")
	} else {
		// profile is a config profile name
		checkProfileCfg(p, c)
	}

	printConfig(p, c)

	return nil
}

func checkEnv() {
	envAk := os.Getenv("AWS_ACCESS_KEY_ID")
	envSt := os.Getenv("AWS_SESSION_TOKEN")

	if len(envAk) > 0 && len(envSt) > 0 {
		if strings.HasPrefix(envAk, "AKIA") {
			log.Errorf("detected static access key env var along with session token env var, this is invalid")
		} else {
			log.Info("environment variables appear sane")
		}
	}
}

func checkRegion(c *config.AwsConfig) {
	// Check that region is set
	if len(c.Region) < 1 {
		log.Errorf("region is not set, it must be specified in the config file or as an environment variable")
	} else {
		log.Info("region is configured in profile or environment variable")
	}
}

func checkProfile(p string) string {
	if len(p) < 1 {
		log.Warn("No profile specified, will only check default section. Provide a profile name for more validation")
		p = "default"
	}
	return p
}

func checkProfileCfg(p string, c *config.AwsConfig) {
	if len(p) > 0 {
		var cfgCreds bool

		if len(c.RoleArn) > 0 {
			// provided profile uses a role, so it must have a valid source_profile attribute
			if len(c.SourceProfile) < 1 {
				log.Errorf("missing source_profile configuration for profile '%s'", p)
			} else {
				// source_profile name must exist in the credentials file
				cfgCreds = checkCredentialProfile(c.SourceProfile)
			}
		} else {
			// not a profile with a role, must have matching section in creds file
			cfgCreds = checkCredentialProfile(p)
		}

		// check for profile creds and env var creds at the same time
		envAk := os.Getenv("AWS_ACCESS_KEY_ID")
		if cfgCreds && len(envAk) > 0 {
			log.Errorf("detected AWS credential environment variables and profile credentials, this may confuse aws-runas")
		} else {
			log.Info("credentials appear sane")
		}
	}
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
	} else {
		log.Info("profile credentials appear sane")
	}

	return true
}

func printConfig(p string, c *config.AwsConfig) {
	fmt.Printf("PROFILE: %s\n", p)
	fmt.Printf("REGION: %s\n", c.Region)
	fmt.Printf("SOURCE PROFILE: %s\n", c.SourceProfile)
	fmt.Printf("SESSION TOKEN DURATION: %s\n", c.SessionDuration)
	fmt.Printf("MFA SERIAL: %s\n", c.MfaSerial)
	fmt.Printf("ROLE ARN: %s\n", c.RoleArn)
	fmt.Printf("EXTERNAL ID: %s\n", c.ExternalID)
	fmt.Printf("ASSUME ROLE CREDENTIAL DURATION: %s\n", c.RoleDuration)
}
