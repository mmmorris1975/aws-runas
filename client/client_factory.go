package client

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/mmmorris1975/aws-runas/client/external"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/credentials/cache"
	"github.com/mmmorris1975/aws-runas/credentials/helpers"
	"os"
	"path/filepath"
	"strings"
)

// singleton cookie jar implementation.
var cookieJar = cache.CookieJar(filepath.Join(cachePath(), ".aws_runas.cookies"))

type Factory struct {
	resolver config.Resolver
	options  *Options
}

// NewClientFactory uses the provides Resolver to determine an appropriate AwsClient for retrieving credential and
// identity information. The supplied Options are used to further affect behavior of the returned AwsClient.
// This is the preferred method for configuring obtaining a client as it is aware of various advanced scenarios such as
// extended Assume Role duration handling, and role chaining.  However it is possible to instantiate and manage a client
// directly, but should be reserved for all but the most advanced/customized use cases.
func NewClientFactory(res config.Resolver, opts *Options) *Factory {
	return &Factory{resolver: res, options: opts}
}

// Get returns an AwsClient for the given configuration, which is expected to be fully resolved and valid.
//
// The client determination logic will check if the SamlUrl config attribute is set (returning a SAML aware client),
// next it will check if the WebIdentityUrl config attribute is set (returning a Web (OIDC) Identity aware client).
// If neither of those is set, it will check the value of the RoleArn config attribute, and if set, will return an
// Assume Role client using IAM credentials. If non of the above situations apply, a client to fetch Session Token
// credentials using IAM credentials will be returned.
func (f *Factory) Get(cfg *config.AwsConfig) (AwsClient, error) {
	if cfg == nil {
		return nil, errors.New("invalid configuration")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if arn.IsARN(cfg.ProfileName) {
		cfg.RoleArn = cfg.ProfileName
		cfg.ProfileName = ""
	}

	opts := []func(*awsconfig.LoadOptions) error{
		//awsconfig.WithLogger(),
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithSharedConfigProfile(cfg.ProfileName),
	}

	f.options.Logger.Debugf("CLIENT CONFIG: %+v", cfg)

	if len(cfg.SamlUrl) > 0 {
		creds, err := f.resolver.Credentials(cfg.SamlUrl)
		if err != nil {
			// non-fatal error, just set empty creds
			creds = new(config.AwsCredentials)
		}
		creds.MergeIn(f.options.CommandCredentials)

		return f.samlClient(cfg, creds, opts...)
	}

	if len(cfg.WebIdentityUrl) > 0 {
		creds, err := f.resolver.Credentials(cfg.WebIdentityUrl)
		if err != nil {
			// non-fatal error, just set empty creds
			creds = new(config.AwsCredentials)
		}
		creds.MergeIn(f.options.CommandCredentials)

		return f.webClient(cfg, creds, opts...)
	}

	if len(cfg.RoleArn) > 0 {
		return f.roleClient(cfg, opts...)
	}

	return f.sessionClient(cfg, opts...)
}

//nolint:funlen
func (f *Factory) samlClient(cfg *config.AwsConfig, creds *config.AwsCredentials, opts ...func(*awsconfig.LoadOptions) error) (AwsClient, error) {
	logger := f.options.Logger
	logger.Debugf("configuring SAML client")

	samlCfg := &SamlRoleClientConfig{
		AuthenticationClientConfig: external.AuthenticationClientConfig{
			Username:                cfg.SamlUsername,
			Password:                f.decodePassword(cfg.SamlUrl, creds.SamlPassword),
			MfaTokenCode:            cfg.MfaCode,
			MfaTokenProvider:        f.options.MfaInputProvider,
			MfaType:                 external.MfaTypeAuto, // not supplied by config resolver, should it be?
			CredentialInputProvider: f.options.CredentialInputProvider,
			IdentityProviderName:    cfg.SamlProvider,
			FederatedUsername:       cfg.FederatedUsername,
		},
		Duration: cfg.RoleCredentialDuration(),
		RoleArn:  cfg.RoleArn,
		Logger:   logger,
	}

	if f.options.EnableCache {
		cacheFile := cacheFileName(".aws_saml_role", cfg.ProfileName, cfg.RoleArn)
		samlCfg.Cache = cache.NewFileCredentialCache(cacheFile)
	}

	// unset opts.Profile, since there's nothing we need it for in the config/credentials files past here
	opts = append(opts, awsconfig.WithSharedConfigProfile(""))
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, err
	}

	if len(cfg.JumpRoleArn) > 0 {
		var roleCache credentials.CredentialCacher
		samlCfg.RoleArn = cfg.JumpRoleArn
		// return role client configured with saml creds
		if f.options.EnableCache {
			samlCfg.Cache = cache.NewFileCredentialCache(cacheFileName(".aws_saml_role", "", cfg.JumpRoleArn))
			roleCache = cache.NewFileCredentialCache(cacheFileName(".aws_assume_role", cfg.ProfileName, cfg.RoleArn))
		}

		logger.Debugf("jump role found, configuring SAML client as base client")
		baseCl := NewSamlRoleClient(awsCfg, cfg.SamlUrl, samlCfg)
		baseCl.samlClient.SetCookieJar(cookieJar)

		logger.Debugf("fetching initial SAML assertion")
		saml, err := baseCl.samlClient.SamlAssertion()
		if err != nil {
			return nil, err
		}
		baseCl.roleProvider.SamlAssertion(saml)

		awsCfg.Credentials = baseCl.roleProvider

		// use assume role client configured with web identity (oidc) creds for role chaining
		roleCfg := &AssumeRoleClientConfig{
			SessionTokenClientConfig: SessionTokenClientConfig{
				Logger:   f.options.Logger,
				Cache:    roleCache,
				Duration: credentials.AssumeRoleDurationDefault, // AWS limits chained creds max duration to 1 hr
			},
			RoleArn:         cfg.RoleArn,
			RoleSessionName: cfg.RoleSessionName,
			ExternalId:      cfg.ExternalId,
		}

		logger.Debugf("configuring assume role client as role client")
		roleCl := NewAssumeRoleClient(awsCfg, roleCfg)
		roleCl.ident = baseCl.samlClient
		return roleCl, nil
	}

	logger.Debugf("no jump role found, only configuring SAML client")
	cl := NewSamlRoleClient(awsCfg, cfg.SamlUrl, samlCfg)
	cl.samlClient.SetCookieJar(cookieJar)

	logger.Debugf("fetching initial SAML assertion")
	saml, _ := cl.samlClient.SamlAssertion()
	cl.roleProvider.SamlAssertion(saml)
	return cl, nil
}

//nolint:funlen
func (f *Factory) webClient(cfg *config.AwsConfig, creds *config.AwsCredentials, opts ...func(*awsconfig.LoadOptions) error) (AwsClient, error) {
	logger := f.options.Logger
	logger.Debugf("configuring Web Identity client")

	webCfg := &WebRoleClientConfig{
		OidcClientConfig: external.OidcClientConfig{AuthenticationClientConfig: external.AuthenticationClientConfig{}},
	}
	webCfg.RoleArn = cfg.RoleArn
	webCfg.Duration = cfg.RoleCredentialDuration()
	webCfg.MfaType = external.MfaTypeAuto // not supplied by config resolver, should it be?
	webCfg.MfaTokenCode = cfg.MfaCode
	webCfg.MfaTokenProvider = f.options.MfaInputProvider
	webCfg.CredentialInputProvider = f.options.CredentialInputProvider
	webCfg.Username = cfg.WebIdentityUsername
	webCfg.Password = f.decodePassword(cfg.WebIdentityUrl, creds.WebIdentityPassword)
	webCfg.FederatedUsername = cfg.FederatedUsername
	webCfg.ClientId = cfg.WebIdentityClientId
	webCfg.RedirectUri = cfg.WebIdentityRedirectUri
	webCfg.IdentityProviderName = cfg.WebIdentityProvider
	webCfg.WebIdentityTokenFile = cfg.WebIdentityTokenFile
	webCfg.Scopes = nil // not supported yet
	webCfg.Logger = logger

	cacheFile := cacheFileName(".aws_web_role", cfg.ProfileName, cfg.RoleArn)
	if f.options.EnableCache {
		webCfg.Cache = cache.NewFileCredentialCache(cacheFile)
	}

	// unset opts.Profile, since there's nothing we need it for in the config/credentials files past here
	opts = append(opts, awsconfig.WithSharedConfigProfile(""))
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, err
	}

	if len(cfg.JumpRoleArn) > 0 {
		var roleCache credentials.CredentialCacher
		webCfg.RoleArn = cfg.JumpRoleArn

		if f.options.EnableCache {
			webCfg.Cache = cache.NewFileCredentialCache(cacheFileName(".aws_web_role", "", cfg.JumpRoleArn))
			roleCache = cache.NewFileCredentialCache(cacheFileName(".aws_assume_role", cfg.ProfileName, cfg.RoleArn))
		}

		logger.Debugf("jump role found, configuring Web Identity client as base client")
		baseCl := NewWebRoleClient(awsCfg, cfg.WebIdentityUrl, webCfg)
		baseCl.webClient.SetCookieJar(cookieJar)

		logger.Debugf("fetching initial Web Identity token")
		tokBytes, err := baseCl.FetchToken(context.Background())
		if err != nil {
			return nil, err
		}
		idToken := credentials.OidcIdentityToken(tokBytes)
		baseCl.roleProvider.WebIdentityToken(&idToken)

		awsCfg.Credentials = baseCl.roleProvider

		// use assume role client configured with web identity (oidc) creds for role chaining
		roleCfg := &AssumeRoleClientConfig{
			SessionTokenClientConfig: SessionTokenClientConfig{
				Logger:   f.options.Logger,
				Cache:    roleCache,
				Duration: credentials.AssumeRoleDurationDefault, // AWS limits chained creds max duration to 1 hr
			},
			RoleArn:         cfg.RoleArn,
			RoleSessionName: cfg.RoleSessionName,
			ExternalId:      cfg.ExternalId,
		}

		logger.Debugf("configuring assume role client as role client")
		roleCl := NewAssumeRoleClient(awsCfg, roleCfg)
		roleCl.ident = baseCl.webClient
		return roleCl, nil
	}

	logger.Debugf("no jump role found, only configuring Web Identity client")
	cl := NewWebRoleClient(awsCfg, cfg.WebIdentityUrl, webCfg)
	cl.webClient.SetCookieJar(cookieJar)
	return cl, nil
}

func (f *Factory) roleClient(cfg *config.AwsConfig, opts ...func(*awsconfig.LoadOptions) error) (*assumeRoleClient, error) {
	logger := f.options.Logger
	logger.Debugf("configuring Assume Role client")

	roleCfg := &AssumeRoleClientConfig{
		SessionTokenClientConfig: SessionTokenClientConfig{
			Duration:      cfg.RoleCredentialDuration(),
			SerialNumber:  cfg.MfaSerial,
			TokenCode:     cfg.MfaCode,
			TokenProvider: f.options.MfaInputProvider,
			Logger:        logger,
		},
		RoleArn:         cfg.RoleArn,
		RoleSessionName: cfg.RoleSessionName,
		ExternalId:      cfg.ExternalId,
	}

	if f.options.EnableCache {
		cacheFile := cacheFileName(".aws_assume_role", cfg.ProfileName, cfg.RoleArn)
		roleCfg.Cache = cache.NewFileCredentialCache(cacheFile)
	}

	if len(cfg.SrcProfile) > 0 {
		logger.Debugf("found source profile, setting as session profile")
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.SrcProfile))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, err
	}

	if cfg.RoleCredentialDuration() <= credentials.AssumeRoleDurationDefault {
		logger.Debugf("detected default or lower role credential duration, using session token credentials")
		// unset MFA Serial Number, it's now the concern of the Session Token client
		roleCfg.SerialNumber = ""

		// configure role client to use session credentials to fetch role credentials and identity
		var sc *sessionTokenClient
		sc, err = f.sessionClient(cfg, opts...)
		if err != nil {
			return nil, err
		}
		awsCfg.Credentials = sc.creds

		cl := NewAssumeRoleClient(awsCfg, roleCfg)
		cl.ident = sc.ident
		return cl, nil
	}

	return NewAssumeRoleClient(awsCfg, roleCfg), nil
}

func (f *Factory) sessionClient(cfg *config.AwsConfig, opts ...func(*awsconfig.LoadOptions) error) (*sessionTokenClient, error) {
	logger := f.options.Logger
	logger.Debugf("configuring Session Token client")

	sesCfg := &SessionTokenClientConfig{
		Duration:      cfg.SessionTokenDuration,
		SerialNumber:  cfg.MfaSerial,
		TokenCode:     cfg.MfaCode,
		TokenProvider: f.options.MfaInputProvider,
		Logger:        logger,
	}

	if f.options.EnableCache {
		cacheFile := cacheFileName(".aws_session_token", cfg.ProfileName, "")
		sesCfg.Cache = cache.NewFileCredentialCache(cacheFile)
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, err
	}

	return NewSessionTokenClient(awsCfg, sesCfg), nil
}

func (f *Factory) decodePassword(url, password string) string {
	pw, err := helpers.NewPasswordEncoder([]byte(url)).Decode(password)
	if err != nil {
		f.options.Logger.Debugf("error decoding password: %s", err.Error())
		pw = password
	}
	return pw
}

func cachePath() string {
	f := awsconfig.DefaultSharedConfigFilename()
	if v, ok := os.LookupEnv("AWS_CONFIG_FILE"); ok {
		f = v
	}
	return filepath.Dir(f)
}

func cacheFileName(prefix, profile, role string) string {
	if len(profile) < 1 && arn.IsARN(role) {
		roleArn, _ := arn.Parse(role)
		roleParts := strings.Split(roleArn.Resource, `/`)
		profile = fmt.Sprintf("%s-%s", roleArn.AccountID, roleParts[len(roleParts)-1])
	}
	return filepath.Join(cachePath(), fmt.Sprintf("%s_%s", prefix, profile))
}
