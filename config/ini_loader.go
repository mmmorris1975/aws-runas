package config

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"gopkg.in/ini.v1"
	"os"
	"strings"
)

// DefaultIniLoader creates a default Loader type to gather configuration and credentials from ini-style data sources.
var DefaultIniLoader = new(iniLoader)

type iniLoader bool

// Config loads fields in the AwsConfig type which support ini-style configuration. The section name to load is specified
// with the profile argument.  If the profile argument is empty, the "default" section will be parsed and loaded. An
// optional variadic sources argument can be provided which can be any of the supported go-ini data source types.  If no
// sources are specified, the default AWS config file (~/.aws/config) is used, unless overridden with the AWS_CONFIG_FILE
// environment variable.
func (l *iniLoader) Config(profile string, sources ...interface{}) (*AwsConfig, error) {
	file, err := resolveConfigSources(sources...)
	if err != nil {
		return nil, err
	}

	c := new(AwsConfig)
	if len(profile) < 1 {
		profile = session.DefaultSharedConfigProfile
	} else {
		// unconditionally attempt to load default profile config
		_ = file.Section(session.DefaultSharedConfigProfile).MapTo(c)
	}

	s, err := lookupProfile(file, profile)
	if err != nil {
		return nil, err
	}

	pc := new(AwsConfig)
	if err := s.MapTo(pc); err != nil {
		return nil, err
	}
	c.MergeIn(pc)

	if len(c.SrcProfile) > 0 {
		src := new(AwsConfig)
		src.ProfileName = c.SrcProfile

		_ = file.Section(session.DefaultSharedConfigProfile).MapTo(src) // add defaults to source profile config

		sp, err := lookupProfile(file, c.SrcProfile)
		if err != nil {
			return nil, err
		}

		if err := sp.MapTo(c); err != nil {
			return nil, err
		}

		if err := sp.MapTo(src); err != nil {
			return nil, err
		}

		c.MergeIn(pc)
		c.sourceProfile = src
	}

	c.ProfileName = profile
	return c, nil
}

// Credentials loads SAML and or Web Identity (OIDC) passwords from ini-style configuration. The section name to load is
// specified with the profile argument.  If the profile argument is empty, the "default" section will be parsed and loaded.
// An optional variadic sources argument can be provided which can be any of the supported go-ini data source types.  If no
// no sources are specified, the default AWS config file (~/.aws/config) is used, unless overridden with the
// AWS_SHARED_CREDENTIALS_FILE environment variable.
func (l *iniLoader) Credentials(profile string, sources ...interface{}) (*AwsCredentials, error) {
	file, err := resolveCredentialSources(sources...)
	if err != nil {
		return nil, err
	}

	if len(profile) < 1 {
		profile = strings.ToLower(ini.DefaultSection)
	}

	s, err := file.GetSection(profile)
	if err != nil {
		return nil, err
	}

	c := new(AwsCredentials)
	if err := s.MapTo(c); err != nil {
		return nil, err
	}

	return c, nil
}

// Roles enumerates the profile sections in the default configuration file and returns a list of section (profile)
// names with contain the role_arn parameter.
func (l *iniLoader) Roles(sources ...interface{}) ([]string, error) {
	file, err := resolveConfigSources(sources...)
	if err != nil {
		return nil, err
	}

	roles := make([]string, 0)
	for _, s := range file.Sections() {
		if s.HasKey("role_arn") {
			roles = append(roles, strings.TrimPrefix(s.Name(), "profile "))
		}
	}
	return roles, nil
}

func resolveConfigSources(sources ...interface{}) (*ini.File, error) {
	f := ini.Empty()

	if sources == nil || len(sources) < 1 {
		src := defaults.SharedConfigFilename()
		if e, ok := os.LookupEnv("AWS_CONFIG_FILE"); ok {
			src = e
		}
		sources = make([]interface{}, 1)
		sources[0] = src
		logger.Debugf("using configuration source %s", src)
	}

	for _, s := range sources {
		if err := f.Append(s); err != nil {
			return nil, err
		}
	}

	return f, nil
}

func resolveCredentialSources(sources ...interface{}) (*ini.File, error) {
	f := ini.Empty()

	if sources == nil || len(sources) < 1 {
		src := defaults.SharedCredentialsFilename()
		if e, ok := os.LookupEnv("AWS_SHARED_CREDENTIALS_FILE"); ok {
			src = e
		}
		sources = make([]interface{}, 1)
		sources[0] = src
		logger.Debugf("using credentials source %s", src)
	}

	for _, s := range sources {
		if err := f.Append(s); err != nil {
			return nil, err
		}
	}

	return f, nil
}

func lookupProfile(f *ini.File, profile string) (*ini.Section, error) {
	s, err := f.GetSection(profile)
	if err != nil {
		// try looking up 'profile name' before failing
		return f.GetSection(fmt.Sprintf("profile %s", profile))
	}
	return s, err
}
