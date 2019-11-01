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
	"sync"
)

// CookieJarFile is a compliant cookiejar.Jar which is able to persist the cookies to a file
type CookieJarFile struct {
	*cookiejar.Jar
	path        string
	mu          sync.Mutex
	siteCookies []*siteCookie
}

type siteCookie struct {
	Site    string
	Cookies []*http.Cookie
}

func (c *siteCookie) merge(cookies []*http.Cookie) {
	// fast path
	if cookies == nil {
		return
	}

	if len(c.Cookies) < 1 {
		c.Cookies = cookies
		return
	}

	cookieMap := make(map[string]*http.Cookie)
	for _, sc := range c.Cookies {
		cookieMap[fmt.Sprintf("%s|%s|%s", sc.Name, sc.Domain, sc.Path)] = sc
	}

	for _, rc := range cookies {
		cookieMap[fmt.Sprintf("%s|%s|%s", rc.Name, rc.Domain, rc.Path)] = rc
	}

	mergedCookies := make([]*http.Cookie, 0)
	for _, v := range cookieMap {
		mergedCookies = append(mergedCookies, v)
	}
	c.Cookies = mergedCookies
}

// NewCookieJarFile creates a new CookieJarFile at the provided path, loading data if the file already exists
func NewCookieJarFile(p string) (*CookieJarFile, error) {
	if len(p) < 1 {
		return nil, fmt.Errorf("invalid file")
	}

	cj := &CookieJarFile{path: p}

	j, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}
	cj.Jar = j

	if err := cj.loadJarFile(p); err != nil {
		return nil, err
	}

	return cj, nil
}

// SetCookies extends the cookiejar.Jar SetCookies() method to save the updated information to disk
func (c *CookieJarFile) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if u == nil || cookies == nil || len(cookies) < 1 {
		return
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return
	}

	c.Jar.SetCookies(u, cookies)
	if err := c.saveJarFile(u, cookies); err != nil {
		// todo ... log?
	}
}

func (c *CookieJarFile) loadJarFile(p string) error {
	cookies := make([]*siteCookie, 0)
	c.siteCookies = cookies

	data, err := ioutil.ReadFile(p)
	if err != nil {
		if _, ok := err.(*os.PathError); !ok {
			return err
		}
		return nil
	}

	// anything less than 2 bytes will be invalid json, so just return the empty cookies list
	if len(data) < 2 {
		return nil
	}

	if err := json.Unmarshal(data, &cookies); err != nil {
		return err
	}

	for _, i := range cookies {
		u, err := url.Parse(i.Site)
		if err != nil {
			return err
		}

		c.Jar.SetCookies(u, i.Cookies)
	}
	c.siteCookies = cookies

	return nil
}

func (c *CookieJarFile) saveJarFile(u *url.URL, cookies []*http.Cookie) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	newSiteCookies := make([]*siteCookie, 0)
	site := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	updated := false

	for _, i := range c.siteCookies {
		if i.Site == site {
			i.merge(cookies)
			updated = true
		}

		newSiteCookies = append(newSiteCookies, i)
	}

	if !updated {
		newSiteCookies = append(newSiteCookies, &siteCookie{
			Site:    site,
			Cookies: cookies,
		})
	}

	c.siteCookies = newSiteCookies

	j, err := json.Marshal(newSiteCookies)
	if err != nil {
		return err
	}

	return writeFile(c.path, j)
}
