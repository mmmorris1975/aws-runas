package lib

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/mbndr/logo"
	"github.com/mmmorris1975/aws-runas/lib/config"
	"os"
	"strings"
	"time"
)

// Profile information from known configuration attributes
// in the aws sdk configuration file
type AWSProfile struct {
	Name            string
	Region          string
	SourceProfile   string  // requires RoleArn
	RoleArn         arn.ARN // requires SourceProfile
	MfaSerial       string  // may be ARN (virtual MFA), or other string (physical MFA)
	ExternalId      string
	RoleSessionName string
	SessionDuration time.Duration
	CredDuration    time.Duration
}

// Interface for managing an ini-formatted configuration file
// providing the ability to retrieve a default profile, profile
// by name, and to build a configuration file based on a
// given list of Roles
type ConfigManager interface {
	GetProfile(name *string) (*AWSProfile, error)
	BuildConfig(roles Roles, mfa *string) error
}

type ConfigManagerOptions struct {
	LogLevel logo.Level
}

// A ConfigManager specific to the aws sdk configuration.  It will use
// the ConfigHandler defined in the provided options, or the DefaultConfigHandler
// which will look up config from the aws config files, and override certain config
// values provided by environment variables.
func NewAwsConfigManager(opts *ConfigManagerOptions) (ConfigManager, error) {
	cm := new(awsConfigManager)

	if opts != nil {
		cm.log = logo.NewSimpleLogger(os.Stderr, opts.LogLevel, "aws-runas.ConfigManager", true)
		cm.opts = opts
	}

	return cm, nil
}

type awsConfigManager struct {
	log  *logo.Logger
	opts *ConfigManagerOptions
}

// Retrieve an AWSProfile by name using the configured ConfigHandler.
// If the specified profile contains a role_arn setting, that value will
// be checked to ensure it's a valid IAM arn, and that the required
// source_profile setting is valid.
func (c *awsConfigManager) GetProfile(p *string) (*AWSProfile, error) {
	if p == nil || len(*p) < 1 {
		return nil, fmt.Errorf("nil or empty profile name")
	}

	cfg := &config.AwsConfig{Name: *p}
	opts := &config.ConfigHandlerOpts{LogLevel: c.opts.LogLevel}

	ch := config.NewSharedCfgConfigHandler(opts)
	if err := ch.Config(cfg); err != nil {
		return nil, err
	}
	profile := new(AWSProfile)

	if len(cfg.RoleArn) > 0 {
		// Validate that RoleArn is a correctly formatted ARN
		a, err := arn.Parse(cfg.RoleArn)
		if err != nil {
			return nil, err
		}

		// Validate that RoleArn is an IAM ARN
		if !strings.HasPrefix(a.String(), IAM_ARN) {
			return nil, fmt.Errorf("role ARN format error, does not start with %s", IAM_ARN)
		}

		// The source_profile config is required (and only valid) with role_arn
		// Ensure that it exists, and is valid
		if len(cfg.SourceProfile) < 1 {
			return nil, fmt.Errorf("role_arn configured, but missing required source_profile")
		}

		profile.RoleArn = a
		profile.SourceProfile = cfg.SourceProfile
		profile.ExternalId = cfg.ExternalId
		profile.RoleSessionName = cfg.RoleSessionName
	}

	env := config.NewEnvConfigHandler(opts)
	if err := env.Config(cfg); err != nil {
		return nil, err
	}

	profile.Region = cfg.GetRegion()
	profile.MfaSerial = cfg.GetMfaSerial()

	cd, err := time.ParseDuration(cfg.GetCredDuration())
	if err != nil {
		cd = ASSUME_ROLE_DEFAULT_DURATION
	}
	profile.CredDuration = cd

	sd, err := time.ParseDuration(cfg.GetSessionDuration())
	if err != nil {
		sd = SESSION_TOKEN_DEFAULT_DURATION
	}
	profile.SessionDuration = sd
	profile.Name = cfg.Name

	return profile, nil
}

// Build an AWS SDK compliant, ini-formatted, configuration file based on the location
// configured during the NewAwsConfigManager() call.  The generated config file will
// have a default section, with all configured roles to use the default section as
// the source_profile, and MFA configured, if the mfa parameter is not nil or empty.
func (c *awsConfigManager) BuildConfig(r Roles, mfa *string) error {
	// TODO build config based on provided Roles using file name in c.config
	// Do NOT overwrite file if it already exists!
	return nil
}
