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
	Log	*logo.Logger
}

func (p *AWSConfigParser) GetProfile(profile *string) (*AWSProfile, error) {
	p.Log.Debug("In GetProfile()")
	section := "default"

	cfg, err := p._readConfig()
	if err != nil {
		return nil, err
	}

	cfg.BlockMode = false

	if *profile != "default" {
		section = "profile " + *profile
	}

	p.Log.Debugf("Looking for profile data in section: '%s'", section)
	profile_t := &AWSProfile{SourceProfile: *profile}
	err = cfg.Section(section).MapTo(profile_t)
	if err != nil {
		return nil, err
	}

	p.Log.Debugf("PROFILE: %+v", *profile_t)
	return profile_t, nil
}

func (p *AWSConfigParser) _readConfig() (*ini.File, error) {
	p.Log.Debug("In _readConfig()")
	cfgFile := filepath.Join(os.Getenv("HOME"), ".aws", "config")

	val, ok := os.LookupEnv("AWS_CONFIG_FILE")
	if ok {
		p.Log.Debug("Using env var for config file location")
		cfgFile = val
	}

	p.Log.Debugf("CONFIG FILE: %s", cfgFile)
	return ini.Load(cfgFile)
}
