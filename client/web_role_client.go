package client

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/mmmorris1975/aws-runas/client/external"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/credentials/cache"
	"github.com/mmmorris1975/aws-runas/identity"
	"github.com/mmmorris1975/aws-runas/shared"
	"os"
	"path/filepath"
	"time"
)

// singleton Web (OIDC) Identity Token cache implementation.
var tokenCache = cache.WebIdentityCache(filepath.Join(cachePath(), ".aws_runas_identity_token.cache"))

type webRoleClient struct {
	webClient    external.WebIdentityClient
	roleProvider credentials.WebRoleProvider
	idpUrl       string
	tokenFile    string
	session      aws.Config
	logger       shared.Logger
}

// WebRoleClientConfig is the means to specify the configuration for the Assume Role with Web Identity operation.
// This includes information necessary to communicate with the external IdP, as well as the configuration for the AWS API calls.
type WebRoleClientConfig struct {
	external.OidcClientConfig
	Cache                credentials.CredentialCacher
	Duration             time.Duration
	RoleArn              string
	WebIdentityTokenFile string
	Logger               shared.Logger
}

// NewWebRoleClient returns a new SAML aware AwsClient for obtaining identity information from the external IdP, and
// for making the AWS Assume Role with Web Identity API call.
func NewWebRoleClient(cfg aws.Config, url string, clientCfg *WebRoleClientConfig) *webRoleClient {
	c := new(webRoleClient)
	c.webClient = external.MustGetWebIdentityClient(clientCfg.IdentityProviderName, url, clientCfg.OidcClientConfig)
	c.idpUrl = url
	c.tokenFile = clientCfg.WebIdentityTokenFile
	c.session = cfg

	c.logger = new(shared.DefaultLogger)
	if clientCfg.Logger != nil {
		c.logger = clientCfg.Logger
	}

	p := credentials.NewWebRoleProvider(cfg, clientCfg.RoleArn)
	p.Duration = clientCfg.Duration
	p.Cache = clientCfg.Cache
	p.Logger = clientCfg.Logger

	if len(p.RoleSessionName) < 2 { // AWS SDK minimum length
		if id, err := c.Identity(); err == nil {
			p.RoleSessionName = id.Username
		} else {
			// escape route value ... matches AWS SDK value defaulting logic
			p.RoleSessionName = fmt.Sprintf("%d", time.Now().UTC().UnixNano())
		}
	}
	c.roleProvider = p
	c.session.Credentials = p

	return c
}

// Identity is the implementation of the IdentityClient interface for retrieving identity information from the external IdP.
func (c *webRoleClient) Identity() (*identity.Identity, error) {
	return c.webClient.Identity()
}

// Roles is the implementation of the IdentityClient interface for retrieving IAM role information from the external IdP
// Web Identity providers are not role aware, so this method will always return an error for this client type.
func (c *webRoleClient) Roles() (*identity.Roles, error) {
	return c.webClient.Roles()
}

// Credentials is the implementation of the CredentialClient interface, and calls CredentialsWithContext with a
// background context.
func (c *webRoleClient) Credentials() (*credentials.Credentials, error) {
	return c.CredentialsWithContext(context.Background())
}

// CredentialsWithContext is the implementation of the CredentialClient interface for retrieving temporary AWS
// credentials using the Assume Role with Web Identity operation.
func (c *webRoleClient) CredentialsWithContext(ctx context.Context) (*credentials.Credentials, error) {
	tok, err := c.FetchToken(ctx)
	if err != nil {
		return nil, err
	}

	tt := credentials.OidcIdentityToken(tok)
	c.roleProvider.WebIdentityToken(&tt)

	v, err := c.roleProvider.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	cred := &credentials.Credentials{
		AccessKeyId:     v.AccessKeyID,
		SecretAccessKey: v.SecretAccessKey,
		Token:           v.SessionToken,
		Expiration:      v.Expires,
		ProviderName:    v.Source,
	}

	return cred, nil
}

// FetchToken is the implementation of the AWS TokenFetch interface for retrieving Web (OIDC) Identity tokens.  If
// configured, this implementation will consult a Web Identity Token file.  Otherwise, if caching is enabled, it will
// be checked.  If no cache is configured or the token retrieved from cache is expired, a new token will be retrieved
// from the external IdP.
func (c *webRoleClient) FetchToken(ctx context.Context) ([]byte, error) {
	// support retrieval via Web Identity token file
	// The file is treated as an always available, always valid, source of truth for providing an identity token
	// It will bypass any communication with an IdP and use the data from the file directly
	if len(c.tokenFile) > 0 {
		return os.ReadFile(c.tokenFile)
	}

	var err error

	tok := tokenCache.Load(c.idpUrl)
	if tok != nil && !tok.IsExpired() {
		return []byte(tok.String()), nil
	}

	tok, err = c.webClient.IdentityTokenWithContext(ctx)
	if err != nil {
		return nil, err
	}

	err = tokenCache.Store(c.idpUrl, tok)
	if err != nil {
		// non-fatal ... just won't have a cached token
		c.logger.Debugf("error writing to token cache: %v", err)
	}

	return []byte(tok.String()), nil
}

// ConfigProvider returns the AWS SDK client.ConfigProvider for this client.
func (c *webRoleClient) ConfigProvider() aws.Config {
	return c.session
}

// ClearCache cleans the cache for this client's OIDC token and AWS credential cache.
func (c *webRoleClient) ClearCache() error {
	c.logger.Debugf("clearing cached web identity token")
	e1 := tokenCache.Clear()
	e2 := c.roleProvider.ClearCache()

	if e1 != nil {
		return e1
	}

	if e2 != nil {
		return e2
	}
	return nil
}
