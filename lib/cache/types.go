package cache

import (
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
	"io/ioutil"
	"os"
	"path/filepath"
)

// CredentialCacher is the interface details to implement AWS credential caching
type CredentialCacher interface {
	Load() (*CacheableCredentials, error)
	Store(*CacheableCredentials) error
}

// CacheableCredentials is a type of AWS credentials which allows caching of the credential values and expiration information
type CacheableCredentials sts.Credentials

// Value converts the CacheableCredentials to a credentials.Value type, setting the ProviderName field to the value
// of the specified provider parameter
func (c *CacheableCredentials) Value(provider string) credentials.Value {
	return credentials.Value{
		AccessKeyID:     *c.AccessKeyId,
		SecretAccessKey: *c.SecretAccessKey,
		SessionToken:    *c.SessionToken,
		ProviderName:    provider,
	}
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	return ioutil.WriteFile(path, data, 0600|os.ModeExclusive)
}
