package cache

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/mmmorris1975/aws-runas/credentials"
	"os"
	"path/filepath"
	"sync"
)

type fileCredentialCache struct {
	path string
	mu   sync.RWMutex
}

// NewFileCredentialCache creates a file-backed credential cache at the specified path.
func NewFileCredentialCache(path string) *fileCredentialCache {
	return &fileCredentialCache{path: path}
}

// Load the cached credentials from the file, if no cached credentials are found an expired set of credentials
// is returned.
func (f *fileCredentialCache) Load() *credentials.Credentials {
	f.mu.RLock()
	defer f.mu.RUnlock()

	creds := new(credentials.Credentials)
	stsCreds := new(types.Credentials)

	data, err := os.ReadFile(f.path)
	if err != nil {
		return creds
	}

	if err := json.Unmarshal(data, stsCreds); err != nil {
		return creds
	}

	creds = credentials.FromStsCredentials(stsCreds)
	if !creds.Value().HasKeys() {
		return new(credentials.Credentials)
	}

	return creds
}

// Store the provided credentials to the file as a serialized JSON representation.
func (f *fileCredentialCache) Store(creds *credentials.Credentials) error {
	if creds == nil || !creds.Value().HasKeys() {
		return credentials.ErrInvalidCredentials
	}

	return f.writeFile(creds)
}

// Clear is the implementation of the CredentialCacher interface to clear data from the cache.  For this file-
// backed implementation, this simply removes the cache file.
func (f *fileCredentialCache) Clear() error {
	// RemoveAll handles single files too, but will not error if file not found
	return os.RemoveAll(f.path)
}

func (f *fileCredentialCache) writeFile(creds *credentials.Credentials) error {
	if err := os.MkdirAll(filepath.Dir(f.path), 0755); err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	tmp, err := os.CreateTemp("", fmt.Sprintf("%s_*.tmp", filepath.Base(f.path)))
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	// this should never return an error, all code paths to get here will have valid/serializable 'data'
	// anything causing an error here is probably a panic-level issue
	_ = json.NewEncoder(tmp).Encode(creds.StsCredentials())

	err = os.Rename(tmp.Name(), f.path)
	if err == nil {
		// make cookie file secure-ish
		_ = os.Chmod(f.path, 0600)
	}
	return err
}
