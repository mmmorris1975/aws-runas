package cache

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"io/ioutil"
	"sync"
	"time"
)

type fileCredentialCache struct {
	path string
	lock sync.Mutex
}

// NewFileCredentialCache creates a file-backed credential cache at the specified path
func NewFileCredentialCache(p string) *fileCredentialCache {
	return &fileCredentialCache{path: p}
}

// Load the cached credentials from the file, if no cached credentials are found an expired set of credentials is returned
func (c *fileCredentialCache) Load() (*CacheableCredentials, error) {
	cred := &CacheableCredentials{Expiration: aws.Time(time.Now())}

	data, err := ioutil.ReadFile(c.path)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, cred); err != nil {
		return nil, err
	}

	return cred, nil
}

// Store the provided credentials to the file as a serialized JSON representation
func (c *fileCredentialCache) Store(cred *CacheableCredentials) error {
	// If we don't test for nil, this code will happily store "null" in the cache file, seems kind of useless
	if cred == nil {
		return fmt.Errorf("nil credentials")
	}

	j, err := json.Marshal(cred)
	if err != nil {
		return err
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	return writeFile(c.path, j)
}
