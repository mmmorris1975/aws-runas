package config

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"gopkg.in/ini.v1"
	"io/ioutil"
	"os"
	"path/filepath"
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
		return c, err
	}

	pc := new(AwsConfig)
	if err := s.MapTo(pc); err != nil {
		return c, err
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
// names which contain the role_arn parameter.
func (l *iniLoader) Roles(sources ...interface{}) ([]string, error) {
	roles := make([]string, 0)
	if p, err := l.Profiles(sources...); err == nil {
		for k, v := range p {
			if v {
				roles = append(roles, k)
			}
		}
	} else {
		return nil, err
	}

	return roles, nil
}

// Profiles returns a map with profile names as keys and a boolean indicating if the profile is a role (determined by
// the presence of the role_arn configuration attribute in the profile.
func (l *iniLoader) Profiles(sources ...interface{}) (map[string]bool, error) {
	file, err := resolveConfigSources(sources...)
	if err != nil {
		return nil, err
	}

	profiles := make(map[string]bool)
	for _, s := range file.Sections() {
		if s.Name() == ini.DefaultSection {
			continue
		}

		var isRole bool
		name := strings.TrimPrefix(s.Name(), "profile ")
		if s.HasKey("role_arn") {
			isRole = true
		}
		profiles[name] = isRole
	}

	return profiles, nil
}

// SaveCredentials writes the data in cred to the AWS credentials file, using the profile name specified by the profile
// parameter. The value of the field containing the password value is stored as-is from the object, any encryption/
// obfuscation is expected to be completed before entering this method.
func (l *iniLoader) SaveCredentials(profile string, cred *AwsCredentials) error {
	src := defaults.SharedCredentialsFilename()
	if e, ok := os.LookupEnv("AWS_SHARED_CREDENTIALS_FILE"); ok {
		src = e
	}

	f, err := ini.Load(src)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}

		var newFile *os.File
		newFile, err = os.Create(src)
		if err != nil {
			return err
		}

		f, _ = ini.Load(newFile)
	}

	if err = f.Section(profile).ReflectFrom(cred); err != nil {
		return err
	}

	return writeFile(f, src, 0600)
}

func writeFile(f *ini.File, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0770); err != nil {
		return err
	}

	tmp, err := ioutil.TempFile(filepath.Dir(dst), fmt.Sprintf("%s.*", filepath.Base(dst)))
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	logger.Debugf("saving credentials")
	if err = f.SaveTo(tmp.Name()); err != nil {
		return err
	}
	_ = tmp.Close()

	if err = os.Rename(tmp.Name(), dst); err == nil {
		_ = os.Chmod(dst, mode)
	}

	return err
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
