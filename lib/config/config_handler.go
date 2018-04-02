package config

import (
	"github.com/mbndr/logo"
	"time"
)

// The struct holding the configuration information for a profile.
// Values are mapped from the SDK config file locations, if using the
// SharedCfgConfigHandler
type AwsConfig struct {
	SourceProfile   string        `ini:"source_profile"` // requires role_arn
	RoleArn         string        `ini:"role_arn"`       // requires source_profile
	MfaSerial       string        `ini:"mfa_serial"`
	ExternalId      string        `ini:"external_id"`
	RoleSessionName string        `ini:"role_session_name"`
	Region          string        `ini:"region"`
	SessionDuration time.Duration `ini:"session_token_duration"`
	CredDuration    time.Duration `ini:"credentials_duration"`
	Name            string
	sourceProfile   *AwsConfig
	defaultProfile  *AwsConfig
}

// Lookup the region value, checking source_profile
// if not found by usual means.
func (c *AwsConfig) GetRegion() string {
	r := c.Region
	if len(r) < 1 {
		if c.defaultProfile != nil {
			r = c.defaultProfile.Region
		}
		if c.sourceProfile != nil {
			r = c.sourceProfile.Region
		}
	}
	return r
}

// Lookup the mfa_serial value, checking source_profile
// if not found by usual means.
func (c *AwsConfig) GetMfaSerial() string {
	m := c.MfaSerial
	if len(m) < 1 {
		if c.defaultProfile != nil {
			m = c.defaultProfile.MfaSerial
		}
		if c.sourceProfile != nil {
			m = c.sourceProfile.MfaSerial
		}
	}
	return m
}

// Lookup the session_token_duration value, checking source_profile
// if not found by usual means.
func (c *AwsConfig) GetSessionDuration() time.Duration {
	d := c.SessionDuration
	if d < 1 {
		if c.defaultProfile != nil {
			d = c.defaultProfile.SessionDuration
		}
		if c.sourceProfile != nil {
			d = c.sourceProfile.SessionDuration
		}

	}
	return d
}

// Lookup the credentials_duration value, checking source_profile
// if not found by usual means.
func (c *AwsConfig) GetCredDuration() time.Duration {
	d := c.CredDuration
	if d < 1 {
		if c.defaultProfile != nil {
			d = c.defaultProfile.CredDuration
		}
		if c.sourceProfile != nil {
			d = c.sourceProfile.CredDuration
		}
	}
	return d
}

// Options used to configure the ConfigHandlers
type ConfigHandlerOpts struct {
	LogLevel logo.Level
}

var DefaultConfigHandlerOpts = &ConfigHandlerOpts{LogLevel: logo.INFO}

// The interface specifying the contract for all conforming ConfigHandlers
type ConfigHandler interface {
	Config(c *AwsConfig) error
}

// The default ConfigHandler, which will lookup configuration in this order:
// Shared configuration
// Environment variables
func DefaultConfigHandler(opts *ConfigHandlerOpts) ConfigHandler {
	return NewChainConfigHandler(
		opts,
		NewSharedCfgConfigHandler(opts),
		NewEnvConfigHandler(opts),
	)
}
