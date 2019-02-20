package cache

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
)

// FileCredentialCache is a CredentialCacher implementation which will cache credentials in a local file
type FileCredentialCache struct {
	Path string
	lock sync.Mutex
}

// Store the provided credentials to the file as a serialized JSON representation
func (c *FileCredentialCache) Store(cred *CacheableCredentials) error {
	// If we don't test for nil, this code will happily store "null" in the cache file, seems kind of useless
	if cred == nil {
		return fmt.Errorf("nil credentials")
	}

	if err := os.MkdirAll(filepath.Dir(c.Path), 0755); err != nil {
		return err
	}

	j, err := json.Marshal(cred)
	if err != nil {
		return err
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	return ioutil.WriteFile(c.Path, j, 0600|os.ModeExclusive)
}

// Fetch the cached credentials from the file
func (c *FileCredentialCache) Fetch() (*CacheableCredentials, error) {
	cred := new(CacheableCredentials)

	data, err := ioutil.ReadFile(c.Path)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, cred); err != nil {
		return nil, err
	}

	return cred, nil
}
