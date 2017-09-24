package main

import (
	"github.com/go-ini/ini"
	"os"
	"path/filepath"
)

type AWSProfile struct {
	SourceProfile string `ini:"source_profile"`
	RoleArn       string `ini:"role_arn"`
	MfaSerial     string `ini:"mfa_serial"`
}

type AWSConfigParser struct {
}

func (p *AWSConfigParser) GetProfile(profile *string) (*AWSProfile, error) {
	section := "default"

	cfg, err := _readConfig()
	if err != nil {
		return nil, err
	}

	cfg.BlockMode = false

	if *profile != "default" {
		section = "profile " + *profile
	}

	profile_t := &AWSProfile{SourceProfile: *profile}
	err = cfg.Section(section).MapTo(profile_t)
	if err != nil {
		return nil, err
	}

	return profile_t, nil
}

func _readConfig() (*ini.File, error) {
	cfgFile := filepath.Join(os.Getenv("HOME"), ".aws", "config")

	val, ok := os.LookupEnv("AWS_CONFIG_FILE")
	if ok {
		cfgFile = val
	}

	return ini.Load(cfgFile)
}
