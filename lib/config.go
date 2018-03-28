package lib

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/go-ini/ini"
	"github.com/mbndr/logo"
	"os"
	"strings"
)

// Prefix for role ARNs and Virtual MFA devices
// (physical MFA devices use device serial number, not ARN)
const IAM_ARN = "arn:aws:iam::"

// Profile information from known configuration attributes
// in the aws sdk configuration file
type AWSProfile struct {
	SourceProfile   string `ini:"source_profile"`
	RoleArn         string `ini:"role_arn"`
	MfaSerial       string `ini:"mfa_serial"`
	ExternalId      string `ini:"external_id"`
	RoleSessionName string `ini:"role_session_name"`
	Region          string `ini:"region"`
	name            string
}

// Interface for managing an ini-formatted configuration file
// providing the ability to retrieve a default profile, profile
// by name, and to build a configuration file based on a
// given list of Roles
type ConfigManager interface {
	DefaultProfile() (*AWSProfile, error)
	GetProfile(name *string) (*AWSProfile, error)
	BuildConfig(roles Roles, mfa *string) error
}

// A ConfigManager specific to the aws sdk configuration.  It will use
// the environment variable AWS_CONFIG_FILE to determine the file to
// load, and if not defined fall back to the SDK default value.
func NewAwsConfigManager(logLevel logo.Level) (ConfigManager, error) {
	c := defaults.SharedConfigFilename()
	e, ok := os.LookupEnv("AWS_CONFIG_FILE")
	if ok && len(e) > 0 {
		c = e
	}

	f, err := ini.Load(c)
	if err != nil {
		return nil, err
	}
	f.BlockMode = false

	logger := logo.NewSimpleLogger(os.Stderr, logLevel, "aws-runas.ConfigManager", true)

	return &awsConfigManager{config: f, log: logger}, nil
}

type awsConfigManager struct {
	config *ini.File
	log    *logo.Logger
}

// Return an AWSProfile for the default aws configuration profile.
// The profile name set in the AWS_DEFAULT_PROFILE environment variable
// and if not set, use a value of "default"
func (c *awsConfigManager) DefaultProfile() (*AWSProfile, error) {
	s := defaultSection()
	p := &AWSProfile{SourceProfile: s, name: s}
	if err := c.profile(p); err != nil {
		return nil, err
	}
	return p, nil
}

// Retrieve an AWSProfile by name.  The default profile will be looked up
// first to provide default settings, and then the profile-specific values
// will be retrieved.  If the specified profile contains a role_arn setting
// that value will be checked to ensure it's a valid IAM arn.
func (c *awsConfigManager) GetProfile(p *string) (*AWSProfile, error) {
	if p == nil || len(*p) < 1 {
		return nil, fmt.Errorf("nil or empty profile name")
	}

	profile, err := c.DefaultProfile()
	if err != nil {
		return nil, err
	}
	profile.name = *p

	if err := c.profile(profile); err != nil {
		return nil, err
	}

	if len(profile.RoleArn) > 0 {
		// Validate that RoleArn is a correctly formatted ARN
		a, err := arn.Parse(profile.RoleArn)
		if err != nil {
			return nil, err
		}

		// Validate that RoleArn is an IAM ARN
		if !strings.HasPrefix(a.String(), IAM_ARN) {
			return nil, fmt.Errorf("role ARN format error, does not start with %s", IAM_ARN)
		}

		// TODO also check that SourceProfile is valid?
		if len(profile.SourceProfile) < 1 {
			return nil, fmt.Errorf("role_arn configured, but missing required source_profile")
		}
	}

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

func (c *awsConfigManager) profile(p *AWSProfile) error {
	name := p.name
	if name != p.SourceProfile {
		name = "profile " + name
	}

	s, err := c.config.GetSection(name)
	if err != nil {
		return err
	}

	if err := s.MapTo(p); err != nil {
		return err
	}
	return nil
}

func defaultSection() string {
	s := "default"
	v, ok := os.LookupEnv("AWS_DEFAULT_PROFILE")
	if ok {
		s = v
	}
	return s
}
