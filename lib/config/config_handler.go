package config

import "github.com/mbndr/logo"

// The struct holding the configuration information for a profile.
// Values are mapped from the SDK config file locations, if using the
// SharedCfgConfigHandler
type AwsConfig struct {
	SourceProfile   string `ini:"source_profile"` // requires role_arn
	RoleArn         string `ini:"role_arn"`       // requires source_profile
	MfaSerial       string `ini:"mfa_serial"`
	ExternalId      string `ini:"external_id"`
	RoleSessionName string `ini:"role_session_name"`
	Region          string `ini:"region"`
	SessionDuration string `ini:"session_token_duration"`
	CredDuration    string `ini:"credentials_duration"`
	Name            string
	sourceProfile   *AwsConfig
	defaultProfile  *AwsConfig
}

// Lookup the region value, checking source_profile
// if not found by usual means.
func (c *AwsConfig) GetRegion() string {
	if len(c.Region) < 1 {
		if c.sourceProfile != nil {
			return c.sourceProfile.Region
		} else {
			return c.defaultProfile.Region
		}
	}
	return c.Region
}

// Lookup the mfa_serial value, checking source_profile
// if not found by usual means.
func (c *AwsConfig) GetMfaSerial() string {
	if len(c.MfaSerial) < 1 {
		if c.sourceProfile != nil {
			return c.sourceProfile.MfaSerial
		} else {
			return c.defaultProfile.MfaSerial
		}
	}
	return c.MfaSerial
}

// Lookup the session_token_duration value, checking source_profile
// if not found by usual means.
func (c *AwsConfig) GetSessionDuration() string {
	if len(c.SessionDuration) < 1 {
		if c.sourceProfile != nil {
			return c.sourceProfile.SessionDuration
		} else {
			return c.defaultProfile.SessionDuration
		}
	}
	return c.SessionDuration
}

// Lookup the credentials_duration value, checking source_profile
// if not found by usual means.
func (c *AwsConfig) GetCredDuration() string {
	if len(c.CredDuration) < 1 {
		if c.sourceProfile != nil {
			return c.sourceProfile.CredDuration
		} else {
			return c.defaultProfile.CredDuration
		}
	}
	return c.CredDuration
}

// Options used to configure the ConfigHandlers
type ConfigHandlerOpts struct {
	LogLevel logo.Level
}

// The interface specifying the contract for all conforming ConfigHandlers
type ConfigHandler interface {
	Config(c *AwsConfig) error
}

// The default ConfigHandler, which will lookup configuration in this order:
// Shared configuration
// Environment variables
// The handler will be configured to use the INFO logging level.
var DefaultConfigHandler = NewChainConfigHandler(
	&ConfigHandlerOpts{LogLevel: logo.INFO},
	NewSharedCfgConfigHandler(&ConfigHandlerOpts{LogLevel: logo.INFO}),
	NewEnvConfigHandler(&ConfigHandlerOpts{LogLevel: logo.INFO}),
)

// default config handling (low to high priority)...
// config files
//  -- shouldn't this be handled by SDK for all but our custom configs?
//  -- may want to grab region and profile from here? (the brad bug)
//  -- still allow certain settings to be rolled up in source profile?
//     - mfa serial, new session and assume role durations
//     - differs with SDK behavior
// env vars
//  -- SDK should pick these up
//  -- values would be expected to be passed on to forked process
// runas options
//  -- profile
//     - Should this be set in the earliest new session request?
//     - Set as AWS_PROFILE env var in runas so it is inherited by forked procs? (this may be bad)
//  -- role arn
//     - Used instead of profile, only applicable with assume role api call
//  -- mfa arn
//     - Only valid if role arn used? (not profile)
//     - only applicable with session token api call
//  -- session cred duration, assume role cred duration
// called command options
//  -- up to command to handle, we'll expose necessary env vars
//
//
// create initial session with share config and verbose credential errors enabled,
// set profile option if it's not an ARN.  Useful when listing roles and mfa ...
// I wonder if we need to account for source_profile settings if they don't reference
// default profile/creds?
//
// Session creds will need to reference source profile if configured for roles,
// Assume Role will use session creds
//
// So at what point do I need to deal with the config file?
