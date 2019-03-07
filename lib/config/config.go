package config

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/go-ini/ini"
	"github.com/mmmorris1975/aws-config/config"
	"github.com/mmmorris1975/aws-runas/lib/credentials"
	"github.com/mmmorris1975/simple-logger"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	// RegionEnvVar is the environment variable to define the AWS region to work in
	RegionEnvVar = "AWS_REGION"
	// DefaultRegionEnvVar is the environment variable to define the default AWS region (if AWS_REGION is not specified)
	DefaultRegionEnvVar = "AWS_DEFAULT_REGION"
	// SessionDurationEnvVar is the environment variable to define the Session Token credential lifetime
	SessionDurationEnvVar = "SESSION_TOKEN_DURATION"
	// RoleDurationEnvVar is the environment variable to define the Assume Role credential lifetime
	RoleDurationEnvVar = "CREDENTIALS_DURATION"
	// MfaSerialEnvVar is the environment variable to define the optional multi-factor authentication serial number or ARN to use to retrieve credentials
	MfaSerialEnvVar = "MFA_SERIAL"
	// ExternalIdEnvVar is the environment variable to define the optional External ID value when getting Assumed Role credentials
	ExternalIdEnvVar = "EXTERNAL_ID"
	// ProfileEnvVar is the environment variable to define the name of the configuration profile (or role ARN) to use to retrieve credentials
	ProfileEnvVar = "AWS_PROFILE"
	// DefaultProfileEnvVar is the environment variable to define the name of the default AWS profile, if different from the SDK default 'default'
	DefaultProfileEnvVar = "AWS_DEFAULT_PROFILE"
	sourceProfileKey     = "source_profile"
)

// ConfigResolver is the interface for retrieving AWS SDK configuration from a source
type ConfigResolver interface {
	ResolveConfig(string) (*AwsConfig, error)
	ListProfiles(bool) []string
}

// AwsConfig is the type used to hold the configuration details retrieved from a given source.
type AwsConfig struct {
	Region          string        `ini:"region"`
	SessionDuration time.Duration `ini:"session_token_duration"`
	RoleDuration    time.Duration `ini:"credentials_duration"`
	MfaSerial       string        `ini:"mfa_serial"`
	RoleArn         string        `ini:"role_arn"`
	ExternalID      string        `ini:"external_id"`
	SourceProfile   string        `ini:"source_profile"`
}

type configResolver struct {
	file          *config.AwsConfigFile
	defaultConfig *AwsConfig
	sourceConfig  *AwsConfig
	profileConfig *AwsConfig
	envConfig     *AwsConfig
	userConfig    *AwsConfig
	log           *simple_logger.Logger
}

// NewConfigResolver provides a default ConfigResolver which will consult the SDK config file ($HOME/.aws/config or
// value of AWS_CONFIG_FILE env var) as a source for configuration resolution, in addition to the provided user config
// data.
func NewConfigResolver(c *AwsConfig) (*configResolver, error) {
	r := new(configResolver)
	f, err := config.NewAwsConfigFile(nil)
	if err != nil {
		return nil, err
	}
	r.file = f

	if c == nil {
		r.userConfig = new(AwsConfig)
	} else {
		r.userConfig = c
	}

	return r, nil
}

// WithLogger configures the provided logger in the config resolver
func (r *configResolver) WithLogger(l *simple_logger.Logger) *configResolver {
	r.log = l
	return r
}

// ListProfiles will return an array of profile names found in the config file.  If the roles arg is false,
// then all profile sections found in the config file will be returned; otherwise only profile sections which
// have the role_arn property will be returned.
func (r *configResolver) ListProfiles(roles bool) []string {
	profiles := make([]string, 0)
	for _, s := range r.file.Sections() {
		if s.Name() == ini.DEFAULT_SECTION {
			continue
		}

		n := strings.TrimPrefix(s.Name(), "profile ")
		if roles {
			if s.HasKey("role_arn") {
				profiles = append(profiles, n)
			}
		} else {
			profiles = append(profiles, n)
		}
	}

	sort.Strings(profiles)
	return profiles
}

// ResolveConfig will generate an AwsConfig object using a variety of sources.
// - First, the default section of the SDK config file is consulted
// - Next, if the profile argument is not a role ARN value, the value is looked up in the SDK config file,
//   additionally resolving any configuration from the profile set in the source_profile attribute
// - Then, apply any configuration settings provided by environment variables.
// - Finally, the above configurations, as well as any configuration specified in NewConfigResolver are merged
//   to provide a consolidated AwsConfig according to the following order of precedence (lowest to highest):
//   - Default config section, source_profile configuration, profile configuration, environment variables, user-supplied config
func (r *configResolver) ResolveConfig(profile string) (*AwsConfig, error) {
	// config file may not exist and config could be baked fully through env vars, so don't barf on errors
	r.ResolveDefaultConfig()

	a, err := arn.Parse(profile)
	if err != nil {
		// not a role arn, should be a profile name in the config file.  If profile not found, or other error,
		// fall through and allow possibility for config to be baked fully through env vars
		r.debug("profile is not a role ARN")
		p, err := r.file.Profile(profile)
		if err == nil {
			src := p.Key(sourceProfileKey).String()
			if len(src) > 0 {
				r.debug("resolving source_profile %s", src)
				// awscli allows a source_profile without a matching profile section in the config, in which case it will
				// only reference that profile name for the section name in the credentials file.  Mimic that behavior
				// by not error checking this call to ResolveProfileConfig()
				r.sourceConfig, _ = r.ResolveProfileConfig(src)
			}

			_, err = r.ResolveProfileConfig(profile)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if strings.HasPrefix(a.Resource, "role/") {
			r.userConfig.RoleArn = a.String()
		} else {
			return nil, fmt.Errorf("invalid role arn format")
		}
	}

	_, err = r.ResolveEnvConfig()
	if err != nil {
		return nil, err
	}

	c := MergeConfig(r.defaultConfig, r.sourceConfig, r.profileConfig, r.envConfig, r.userConfig)
	if c.SessionDuration < 1 {
		c.SessionDuration = credentials.SessionTokenDefaultDuration
	}

	if c.RoleDuration < 1 {
		c.RoleDuration = credentials.AssumeRoleDefaultDuration
	}

	r.debug("MERGED CONFIG: %+v", *c)
	return c, nil
}

// ResolveDefaultConfig will look up configuration information in the 'default' section of the AWS SDK configuration
// file.  The default section name can be overridden by setting the AWS_DEFAULT_PROFILE environment variable.  The config
// file location can be overridden by setting the AWS_CONFIG_FILE environment variable.  While any valid configuration
// property may be specified in the default section, this method will only return the settings for the 'region',
// 'session_token_duration', and 'credentials_duration' properties, to avoid possible conflict with role-specific configuration
func (r *configResolver) ResolveDefaultConfig() (*AwsConfig, error) {
	p := config.DefaultProfileName
	if v, ok := os.LookupEnv(DefaultProfileEnvVar); ok {
		p = v
	}

	s, err := r.file.Profile(p)
	if err != nil {
		return nil, err
	}

	// Unmarshal any valid ini token for the struct, but only actually set values we're allowing
	// For example, don't allow mfa_serial to be passed through from default config
	c := new(AwsConfig)
	if err := s.MapTo(c); err != nil {
		return nil, err
	}
	r.defaultConfig = &AwsConfig{Region: c.Region, SessionDuration: c.SessionDuration, RoleDuration: c.RoleDuration, SourceProfile: p}

	r.debug("DEFAULT CONFIG: %+v", *r.defaultConfig)
	return r.defaultConfig, nil
}

// ResolveProfileConfig will resolve the configuration for the section specified by the profile argument, using the
// data mapping specified in the AwsConfig type fields.  This method will not recursively resolve configuration if
// the source_profile attribute is set.  If a source_profile is set for the provided named profile, a non-empty string
// value will be present in the returned AwsConfig.SourceProfile field, which can be used as the argument to another
// call to this method to resolve the source_profile configuration properties.
func (r *configResolver) ResolveProfileConfig(profile string) (*AwsConfig, error) {
	s, err := r.file.Profile(profile)
	if err != nil {
		return nil, err
	}

	c := new(AwsConfig)
	if err := s.MapTo(c); err != nil {
		return nil, err
	}
	r.profileConfig = c

	r.debug("PROFILE '%s' CONFIG: %+v", profile, *r.profileConfig)
	return r.profileConfig, nil
}

// Consult the following environment variables for setting configuration values:
// AWS_DEFAULT_REGION, AWS_REGION (will override AWS_DEFAULT_REGION), MFA_SERIAL, EXTERNAL_ID,
// SESSION_TOKEN_DURATION, CREDENTIALS_DURATION
func (r *configResolver) ResolveEnvConfig() (*AwsConfig, error) {
	c := new(AwsConfig)

	if v, ok := os.LookupEnv(DefaultRegionEnvVar); ok {
		c.Region = v
	}

	if v, ok := os.LookupEnv(RegionEnvVar); ok {
		c.Region = v
	}

	if v, ok := os.LookupEnv(MfaSerialEnvVar); ok {
		c.MfaSerial = v
	}

	if v, ok := os.LookupEnv(ExternalIdEnvVar); ok {
		c.ExternalID = v
	}

	if v, ok := os.LookupEnv(SessionDurationEnvVar); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, err
		}
		c.SessionDuration = d
	}

	if v, ok := os.LookupEnv(RoleDurationEnvVar); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, err
		}
		c.RoleDuration = d
	}

	r.envConfig = c
	r.debug("ENV CONFIG: %+v", *r.envConfig)
	return r.envConfig, nil
}

// MergeConfig will merge the provided list of AwsConfig types to a single value.  Precedence is based on the order
// of the item in the list, with later items overriding values specified in earlier items.  Only non-nil AwsConfig types
// will be considered, and the field inside the AwsConfig item must be a non-zero value to override a prior setting
func MergeConfig(conf ...*AwsConfig) *AwsConfig {
	cfg := new(AwsConfig)

	for _, c := range conf {
		if c != nil {
			if len(c.Region) > 0 {
				cfg.Region = c.Region
			}

			if len(c.MfaSerial) > 0 {
				cfg.MfaSerial = c.MfaSerial
			}

			if len(c.RoleArn) > 0 {
				cfg.RoleArn = c.RoleArn
			}

			if len(c.ExternalID) > 0 {
				cfg.MfaSerial = c.MfaSerial
			}

			if len(c.SourceProfile) > 0 {
				cfg.SourceProfile = c.SourceProfile
			}

			if len(c.ExternalID) > 0 {
				cfg.ExternalID = c.ExternalID
			}

			if c.SessionDuration > 0 {
				cfg.SessionDuration = c.SessionDuration
			}

			if c.RoleDuration > 0 {
				cfg.RoleDuration = c.RoleDuration
			}
		}
	}

	return cfg
}

func (r *configResolver) debug(f string, v ...interface{}) {
	if r.log != nil {
		r.log.Debugf(f, v...)
	}
}
