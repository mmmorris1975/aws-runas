package config

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/go-ini/ini"
	"github.com/mbndr/logo"
	"os"
)

// A ConfigHandler which will get configuration from the AWS SDK configuration
// files.  The AWS SDK buries many of the details of the SDK configuration in
// the guts of the session object, and only exposes things like region and
// profile name.  This will externalize the rest of the configuration for use.
type SharedCfgConfigHandler struct {
	confFile   string
	credFile   string
	profile    string
	defProfile string
	log        *logo.Logger
}

// Create a new ConfigHandler which will lookup configuration using SDK default
// values for the config file locations and profile name.  To affect the settings
// of those values at creation, provide the common SDK environment variables.
//
// AWS_CONFIG_FILE will set the shared configuration file location to read the config
// AWS_SHARED_CREDENTIALS_FILE will set the credentials file location
// AWS_DEFAULT_PROFILE will set the default profile to gather initial configuration
// AWS_PROFILE will set the profile name to gather the configuration
func NewSharedCfgConfigHandler(opts *ConfigHandlerOpts) ConfigHandler {
	h := SharedCfgConfigHandler{
		confFile: defaults.SharedConfigFilename(),
		credFile: defaults.SharedCredentialsFilename(),
		//profile:    session.DefaultSharedConfigProfile,
		defProfile: session.DefaultSharedConfigProfile,
	}
	if opts != nil {
		h.log = logo.NewSimpleLogger(os.Stderr, opts.LogLevel, "SharedCfgConfigHandler", true)
	}

	return &h
}

// Gather the configuration from the config file locations.  First, configuration
// from the default profile is loaded, then (if configured) settings for the profile
// are loaded.  If the profile also specifies a source_profile and role_arn, the
// data from the source_profile is also obtained.
func (h *SharedCfgConfigHandler) Config(c *AwsConfig) error {
	if c == nil {
		return nil
	}

	if len(c.Name) > 0 {
		h.Profile(c.Name)
	}

	h.readEnv()

	if err := h.loadProfile(c); err != nil {
		return err
	}

	if c.sourceProfile != nil {
		c.sourceProfile.Name = c.SourceProfile
	}
	return nil
}

// Explicitly set the value of the profile to get configuration.  This will override any
// value set in the constructor or environment variables.
func (h *SharedCfgConfigHandler) Profile(p string) {
	h.profile = p
}

func (h *SharedCfgConfigHandler) loadProfile(c *AwsConfig) error {
	f, err := ini.Load(h.credFile, h.confFile)
	if err != nil {
		return err
	}

	// load default section
	c.defaultProfile = new(AwsConfig)
	if err := h.mapConfig(h.defProfile, c.defaultProfile, f); err != nil {
		// log errors only
		if h.log != nil {
			h.log.Debugf("Error loading default profile: %s: %v", h.defProfile, err)
		}
	}

	// load profile section (bare profile name first)
	if err := h.mapConfig(h.profile, c, f); err != nil {
		return err
	}

	// SDK says that source_profile only valid with role_arn
	if len(c.SourceProfile) > 0 && len(c.RoleArn) > 0 {
		c.sourceProfile = new(AwsConfig)
		if err := h.mapConfig(c.SourceProfile, c.sourceProfile, f); err != nil {
			return err
		}
	}
	c.Name = h.profile

	return nil
}

func (h *SharedCfgConfigHandler) mapConfig(p string, c *AwsConfig, f *ini.File) error {
	// first try lookup of bare profile name
	s, err := f.GetSection(p)
	if err != nil {
		//h.log.Warnf("Profile lookup of '%s' failed, trying 'profile %s'", p, p)
		s, err = f.GetSection(fmt.Sprintf("profile %s", p))
		if err != nil {
			return err
		}
	}

	if err := s.MapTo(c); err != nil {
		return err
	}
	c.Name = p
	return nil
}

func (h *SharedCfgConfigHandler) readEnv() {
	conf, ok := os.LookupEnv("AWS_CONFIG_FILE")
	if ok {
		h.confFile = conf
	}

	cred, ok := os.LookupEnv("AWS_SHARED_CREDENTIALS_FILE")
	if ok {
		h.credFile = cred
	}

	dp, ok := os.LookupEnv("AWS_DEFAULT_PROFILE")
	if ok {
		h.defProfile = dp
		//h.profile = dp
	}

	p, ok := os.LookupEnv("AWS_PROFILE")
	if ok {
		h.profile = p
	}
}
