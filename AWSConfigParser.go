package main

import (
	"github.com/go-ini/ini"
	"github.com/mbndr/logo"
	"os"
	"path/filepath"
)

type AWSProfile struct {
	SourceProfile string `ini:"source_profile"`
	RoleArn       string `ini:"role_arn"`
	MfaSerial     string `ini:"mfa_serial"`
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
	cfgFile := filepath.Join(os.Getenv("HOME"), ".aws", "config")

	val, ok := os.LookupEnv("AWS_CONFIG_FILE")
	if ok {
		p.Logger.Debug("Using env var for config file location")
		cfgFile = val
	}

	p.Logger.Debugf("CONFIG FILE: %s", cfgFile)
	return ini.Load(cfgFile)
}
