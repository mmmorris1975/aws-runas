package config

import "github.com/mmmorris1975/aws-runas/shared"

type resolver struct {
	loader     Loader
	defConfig  *AwsConfig
	defCreds   *AwsCredentials
	config     *AwsConfig
	creds      *AwsCredentials
	resolveSrc bool
}

// NewResolver configures a Resolver using the provided loader. If the resolveSrc argument is true, then any source
// profile configuration is added to the overall configuration before applying profile-specific configuration.  This
// provides a way to manage common configuration in a more DRY way.
func NewResolver(loader Loader, resolveSrc bool) *resolver {
	return &resolver{
		loader:     loader,
		defConfig:  new(AwsConfig),
		defCreds:   new(AwsCredentials),
		resolveSrc: resolveSrc,
	}
}

func (r *resolver) WithLogger(l shared.Logger) *resolver {
	logger = l // package-level logger
	return r
}

// WithDefaultConfig is a fluent method for setting an initial/default configuration object, which will be used as the
// base configuration for any calls to Config().
func (r *resolver) WithDefaultConfig(config *AwsConfig) *resolver {
	if config != nil {
		r.defConfig = config
	}
	return r
}

// WithDefaultCredentials is a fluent method for setting an initial/default configuration object, which will be used as
// the base credentials for any calls to Credentials().
func (r *resolver) WithDefaultCredentials(creds *AwsCredentials) *resolver {
	if creds != nil {
		r.defCreds = creds
	}
	return r
}

// MergeConfig sets additional configuration for the resolver, and returns the updated configuration.
// For best effect, use after calling Config()
func (r *resolver) MergeConfig(cfg ...*AwsConfig) *AwsConfig {
	if r.config == nil {
		r.config = r.defConfig
	}
	r.config.MergeIn(cfg...)
	return r.config
}

// MergeCredentials sets additional credentials for the resolver, and returns th updated credentials.
// For best effect, use after calling Credentials()
func (r *resolver) MergeCredentials(creds ...*AwsCredentials) *AwsCredentials {
	if r.creds == nil {
		r.creds = r.defCreds
	}
	r.creds.MergeIn(creds...)
	return r.creds
}

// Config is the implementation of the Resolver interface to build a coherent AwsConfig object
func (r *resolver) Config(profile string) (*AwsConfig, error) {
	c, err := r.loader.Config(profile)
	if err != nil {
		return nil, err
	}

	r.config = new(AwsConfig)
	r.config.MergeIn(r.defConfig)

	if r.resolveSrc && c.sourceProfile != nil {
		r.config.MergeIn(c.sourceProfile)
	}
	r.config.MergeIn(c)
	r.config.ProfileName = profile

	return r.config, nil
}

// Credentials is the implementation of the Resolver interface to build a coherent AwsCredentials object
func (r resolver) Credentials(profile string) (*AwsCredentials, error) {
	c, err := r.loader.Credentials(profile)
	if err != nil {
		return nil, err
	}

	r.creds = new(AwsCredentials)
	r.creds.MergeIn(r.defCreds)
	r.creds.MergeIn(c)

	return r.creds, nil
}
