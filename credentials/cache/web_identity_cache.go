package cache

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/mmmorris1975/aws-runas/credentials"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
)

var tokenCache map[string]*webIdentityCache

// WebIdentityCache provides a file-backed IdentityTokenCacher implementation at the specified path.
var WebIdentityCache = func(path string) *webIdentityCache {
	if tokenCache == nil {
		tokenCache = make(map[string]*webIdentityCache)
	}

	if v, ok := tokenCache[path]; ok {
		return v
	}

	wic, err := newWebIdentityCache(path)
	if err != nil {
		panic(err)
	}

	tokenCache[path] = wic
	return wic
}

type webIdentityCache struct {
	path  string
	mu    sync.RWMutex
	cache map[string]*credentials.OidcIdentityToken
}

// force public access through WebIdentityCache() so we have better safety for concurrent access to individual files
func newWebIdentityCache(path string) (*webIdentityCache, error) {
	// ensure all intermediate directories exist
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}

	c := &webIdentityCache{path: path, cache: make(map[string]*credentials.OidcIdentityToken)}
	if err := c.loadCache(); err != nil {
		return nil, err
	}

	return c, nil
}

// Load is the implementation of the IdentityTokenCacher interface to load data from the cache. If no token is found,
// or the token is expired, nil will be returned
func (c *webIdentityCache) Load(url string) *credentials.OidcIdentityToken {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if tok, ok := c.cache[tokenCacheKey(url)]; ok && !tok.IsExpired() {
		return tok
	}
	return nil
}

// Store is the implementation of the IdentityTokenCacher interface to write data to the cache. If an empty url, or
// invalid identity token is detected, the cache will not be updated.
func (c *webIdentityCache) Store(url string, token *credentials.OidcIdentityToken) error {
	if len(url) < 1 || token == nil || len(*token) < 1 {
		return errors.New("invalid token data or url")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[tokenCacheKey(url)] = token
	return c.flush()
}

// Clear is the implementation of the IdentityTokenCacher interface to clear data from the cache.  For this file-
// backed implementation, this simply removes the cache file
func (c *webIdentityCache) Clear() error {
	// RemoveAll handles single files too, but will not error if file not found
	return os.RemoveAll(c.path)
}

func (c *webIdentityCache) loadCache() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := ioutil.ReadFile(c.path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err // some kind of I/O error we probably care about
		}
		// file does not exist, this is not an error, just return
		return nil
	}

	if data != nil && len(data) > 2 {
		if err := json.Unmarshal(data, &c.cache); err != nil {
			// todo handle (log?) error
			// this is non-fatal, just rewrite a fresh cache without the old data
		}
	}

	return nil
}

func (c *webIdentityCache) flush() error {
	tmp, err := ioutil.TempFile("", ".aws_runas_id_tokens_*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	// this should never return an error, all code paths to get here will have valid/serializable 'data'
	// anything causing an error here is probably a panic-level issue
	_ = json.NewEncoder(tmp).Encode(c.cache)

	err = os.Rename(tmp.Name(), c.path)
	if err == nil {
		// make cookie file secure-ish
		_ = os.Chmod(c.path, 0600)
	}
	return err
}

// The MD5 [16]byte hash isn't directly serializable, use hex string encoding
func tokenCacheKey(url string) string {
	sum := md5.Sum([]byte(url))
	return hex.EncodeToString(sum[:])
}
