package config

import (
	"github.com/mattn/go-isatty"
	"github.com/mbndr/logo"
	"os"
	"time"
)

// AwsConfig holds the configuration information for a profile.
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

// GetRegion will lookup the region value, checking source_profile
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

// GetMfaSerial will lookup the mfa_serial value, checking source_profile
// if not found by usual means.
func (c *AwsConfig) GetMfaSerial() string {
	m := c.MfaSerial
	if len(m) < 1 {
		// Don't check if mfa_serial is part of default profile, it will mess with
		// stand-alone profiles (ones without source_profile) and prevent those
		// from authenticating.  The only valid way mfa_serial should come in is
		// via the profile directly or referenced in the source profile
		if c.sourceProfile != nil {
			m = c.sourceProfile.MfaSerial
		}
	}
	return m
}

// GetSessionDuration will lookup the session_token_duration value, checking
// source_profile if not found by usual means.
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

// GetCredDuration will lookup the credentials_duration value, checking
// source_profile if not found by usual means.
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

// ConfigHandlerOpts provides settings used to configure the ConfigHandlers
type ConfigHandlerOpts struct {
	LogLevel logo.Level
}

// DefaultConfigHandlerOpts is a default/sane set of options for a ConfigHandler
var DefaultConfigHandlerOpts = &ConfigHandlerOpts{LogLevel: logo.INFO}

// ConfigHandler is the interface specifying the contract for all conforming ConfigHandlers
type ConfigHandler interface {
	Config(c *AwsConfig) error
}

// DefaultConfigHandler will lookup configuration in this order:
// Shared configuration
// Environment variables
func DefaultConfigHandler(opts *ConfigHandlerOpts) ConfigHandler {
	return NewChainConfigHandler(
		opts,
		NewSharedCfgConfigHandler(opts),
		NewEnvConfigHandler(opts),
	)
}

// NewLogger provides a consistent way to create a "terminal aware" logger
func NewLogger(name string, level logo.Level) *logo.Logger {
	w := os.Stderr
	isTerm := isatty.IsTerminal(w.Fd()) || isatty.IsCygwinTerminal(w.Fd())
	return logo.NewSimpleLogger(w, level, name, isTerm)
}
