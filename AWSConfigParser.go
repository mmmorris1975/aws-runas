package main

import (
	"fmt"
	"github.com/go-ini/ini"
	"github.com/mbndr/logo"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// Prefix for role ARNs and Virtual MFA devices
// (physical MFA devices use device serial number, not ARN)
const IAM_ARN = "arn:aws:iam::"

type AWSProfile struct {
	SourceProfile string `ini:"source_profile"`
	RoleArn       string `ini:"role_arn"`
	MfaSerial     string `ini:"mfa_serial"`
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
	err := cfg.Section(section).MapTo(profile_t)
	if err != nil {
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

	if len(profile_t.MfaSerial) < 1 && *profile != profile_t.SourceProfile {
		p.Logger.Debug("No mfa_serial config found in profile, checking source_profile")
		src_profile_t, err := p.lookupProfile(&profile_t.SourceProfile, cfg)
		if err == nil {
			profile_t.MfaSerial = src_profile_t.MfaSerial
		} else {
			p.Logger.Debugf("Ignoring error while looking up source_profile info: %+v", err)
		}
	}

	p.Logger.Debugf("PROFILE: %+v", *profile_t)
	return profile_t, nil
}

func (p *AWSConfigParser) _readConfig() (*ini.File, error) {
	p.Logger.Debug("In _readConfig()")

	u, err := user.Current()
	if err != nil {
		p.Logger.Debug("Unable to determine current user: %+v", err)
		return nil, err
	}

	cfgFile := filepath.Join(u.HomeDir, ".aws", "config")

	val, ok := os.LookupEnv("AWS_CONFIG_FILE")
	if ok {
		p.Logger.Debug("Using env var for config file location")
		cfgFile = val
	}

	p.Logger.Debugf("CONFIG FILE: %s", cfgFile)
	return ini.Load(cfgFile)
}
