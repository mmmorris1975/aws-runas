package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/go-ini/ini"
	"github.com/mbndr/logo"
	"os"
	"strings"
)

// Prefix for role ARNs and Virtual MFA devices
// (physical MFA devices use device serial number, not ARN)
const IAM_ARN = "arn:aws:iam::"

type AWSProfile struct {
	SourceProfile string `ini:"source_profile"`
	RoleArn       string `ini:"role_arn"`
	MfaSerial     string `ini:"mfa_serial"`
	Region        string `ini:"region"`
}

func NewAWSProfile(profile_name *string, mfa_arn *string) (*AWSProfile, error) {
	var profile_cfg *AWSProfile
	var err error

	if strings.HasPrefix(*profile_name, IAM_ARN) {
		// Don't set SourceProfile to allow the SDK to use the default CredentialProvider
		// to look up API keys using the internal SDK credential lookup logic.  It makes the
		// cache file name a bit wonky, but that's not a big deal.
		profile_cfg = &AWSProfile{
			RoleArn: *profile_name,
		}
	} else {
		// profile arg looks like a profile name
		cfgParser := AWSConfigParser{Logger: logo.NewSimpleLogger(os.Stderr, logLevel, "aws-runas.AWSConfigParser", true)}
		profile_cfg, err = cfgParser.GetProfile(profile_name)
		if err != nil {
			return nil, err
		}
	}

	if len(*mfa_arn) > 0 {
		profile_cfg.MfaSerial = *mfa_arn
	}

	return profile_cfg, nil
}

type AWSConfigParser struct {
	Logger *logo.Logger
}

func (p *AWSConfigParser) lookupProfile(profile *string, cfg *ini.File) (*AWSProfile, error) {
	p.Logger.Debug("In lookupProfile()")
	section := "default"

	if *profile != "default" {
		section = "profile " + *profile
	}

	p.Logger.Debugf("Looking for profile data in section: '%s'", section)
	profile_t := &AWSProfile{SourceProfile: *profile}

	s, err := cfg.GetSection(section)
	if err != nil {
		return nil, err
	}
	if err := s.MapTo(profile_t);err != nil {
		return nil, err
	}

	if len(profile_t.RoleArn) > 0 && !strings.HasPrefix(profile_t.RoleArn, IAM_ARN) {
		return nil, fmt.Errorf("Role ARN format error, does not start with %s", IAM_ARN)
	}

	return profile_t, nil
}

func (p *AWSConfigParser) GetProfile(profile *string) (*AWSProfile, error) {
	p.Logger.Debug("In GetProfile()")

	cfg, err := p._readConfig()
	if err != nil {
		return nil, err
	}

	cfg.BlockMode = false

	profile_t, err := p.lookupProfile(profile, cfg)
	if err != nil {
		return nil, err
	}

	if *profile != profile_t.SourceProfile {
		p.Logger.Debug("Checking source_profile for additional configuration")
		src_profile_t, err := p.lookupProfile(&profile_t.SourceProfile, cfg)
		if err != nil {
			p.Logger.Debugf("Error looking up source_profile: %v", err)
		} else {
			if len(profile_t.MfaSerial) < 1 {
				p.Logger.Debug("Setting mfa serial from source profile")
				profile_t.MfaSerial = src_profile_t.MfaSerial
			}

			if len(profile_t.Region) < 1 {
				p.Logger.Debugf("Setting region from source profile")
				profile_t.Region = src_profile_t.Region
			}
		}
	}

	p.Logger.Debugf("PROFILE: %+v", *profile_t)
	return profile_t, nil
}

func (p *AWSConfigParser) _readConfig() (*ini.File, error) {
	p.Logger.Debug("In _readConfig()")
	cfgFile := defaults.SharedConfigFilename()

	val, ok := os.LookupEnv("AWS_CONFIG_FILE")
	if ok {
		p.Logger.Debug("Using env var for config file location")
		cfgFile = val
	}

	p.Logger.Debugf("CONFIG FILE: %s", cfgFile)
	return ini.Load(cfgFile)
}
