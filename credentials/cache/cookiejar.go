package cache

import (
	"encoding/json"
	"fmt"
	"golang.org/x/net/publicsuffix"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var cjMap map[string]*cookieJar

// CookieJar provides a file-backed cookie jar implementation at the specified path.
var CookieJar = func(path string) *cookieJar {
	if cjMap == nil {
		cjMap = make(map[string]*cookieJar)
	}

	if v, ok := cjMap[path]; ok {
		return v
	}

	cj, err := newCookieJar(path)
	if err != nil {
		panic(err)
	}

	cjMap[path] = cj
	return cj
}

type cookieJar struct {
	path string
	mu   sync.RWMutex
	jar  *cookiejar.Jar
}

// force public access through CookieJar() so we have better safety for concurrent access to individual files.
func newCookieJar(path string) (*cookieJar, error) {
	// ensure all intermediate directories exist
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}

	// this never errors
	j, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})

	cj := &cookieJar{path: path, jar: j}
	if err := cj.loadCache(); err != nil {
		return nil, err
	}

	return cj, nil
}

// SetCookies is the implementation of the http.CookieJar interface which will add cookies to the in-memory cache,
// and flush that data to a file.  Invalid url or cookie information will not be written.
func (c *cookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if u == nil || !strings.HasPrefix(u.Scheme, "http") || cookies == nil || len(cookies) < 1 {
		// nothing worth storing
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.jar.SetCookies(u, cookies)
	_ = c.flush(u, cookies) // todo handle (log?) error
}

// Cookies is the implementation of the http.CookieJar interface to retrieve cookies from the cache.
func (c *cookieJar) Cookies(u *url.URL) []*http.Cookie {
	if u == nil {
		return []*http.Cookie{}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.jar.Cookies(u)
}

func (c *cookieJar) loadCache() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cache, err := readCache(c.path)
	if err != nil {
		// this will be some kind of I/O error other than File Not Found, so we probably should care
		return err
	}

	var u *url.URL
	for k, v := range cache {
		u, err = url.Parse(k)
		if err != nil {
			// key isn't a valid url ... just skip it (maybe log?)
			continue
		}
		c.jar.SetCookies(u, v)
	}
	return nil
}

// WARNING - be sure to Lock() before calling this method.
func (c *cookieJar) flush(u *url.URL, cookies []*http.Cookie) error {
	// we'll need this read-before-update step to ensure we have a complete view of the cookies, since we can't
	// dump the entire in-memory jar (details hidden)
	cache, err := readCache(c.path)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("%s://%s", u.Scheme, u.Hostname())
	cache[key] = merge(cache[key], cookies)

	return writeCache(c.path, cache)
}

func merge(src []*http.Cookie, new []*http.Cookie) []*http.Cookie {
	mergeMap := make(map[string]*http.Cookie, len(src))

	for _, v := range append(src, new...) {
		mergeMap[strings.Join([]string{v.Name, v.Domain, v.Path}, `|`)] = v
	}

	i := 0
	cookies := make([]*http.Cookie, len(mergeMap))
	for _, v := range mergeMap {
		cookies[i] = v
		i++
	}

	return cookies
}

// WARNING - if called outside of loadCache() or flush(), be sure to RLock() or Lock() before entering!
func readCache(path string) (map[string][]*http.Cookie, error) {
	cookies := make(map[string][]*http.Cookie)

	data, err := ioutil.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err // some kind of I/O error we probably care about
		}
		// file does not exist, this is not an error, just return empty map
		return cookies, nil
	}

	if len(data) > 2 {
		// this is non-fatal, just rewrite a fresh cache without the old data
		_ = json.Unmarshal(data, &cookies)
	}

	return cookies, nil
}

// WARNING - if called outside of flush(), be sure Lock() before entering!
func writeCache(path string, data map[string][]*http.Cookie) error {
	tmp, err := ioutil.TempFile(filepath.Dir(path), ".aws_runas_cookies_*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	// this should never return an error, all code paths to get here will have valid/serializable 'data'
	// anything causing an error here is probably a panic-level issue
	_ = json.NewEncoder(tmp).Encode(data)

	err = os.Rename(tmp.Name(), path)
	if err == nil {
		// make cookie file secure-ish
		_ = os.Chmod(path, 0600)
	}
	return err
}
