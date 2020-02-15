package cache

import (
	"net/http"
	"net/url"
	"os"
	"testing"
)

func TestNewCookieJarFile(t *testing.T) {
	t.Run("new file", func(t *testing.T) {
		f, err := NewCookieJarFile("new-file")
		if err != nil {
			t.Error(err)
			return
		}

		if f.path != "new-file" || len(f.siteCookies) > 0 {
			t.Error("data mismatch")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		if _, err := NewCookieJarFile(""); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestCookieJarFile_SetCookiesErrors(t *testing.T) {
	t.Run("all empty", func(t *testing.T) {
		c, err := NewCookieJarFile("cookie-jar")
		if err != nil {
			t.Error(err)
			return
		}

		c.SetCookies(new(url.URL), []*http.Cookie{})
		defer os.Remove(c.path)

		if len(c.siteCookies) > 0 {
			t.Error("unexpectedly stored an empty cookie with an empty url")
		}
	})

	t.Run("nil url", func(t *testing.T) {
		c, err := NewCookieJarFile("cookie-jar")
		if err != nil {
			t.Error(err)
			return
		}

		c.SetCookies(nil, []*http.Cookie{{
			Name:   "nil-url",
			Value:  "aCookie",
			Path:   "/",
			Domain: "example.org",
		}})
		defer os.Remove(c.path)

		if len(c.siteCookies) > 0 {
			t.Error("unexpectedly stored a cookie with a nil url")
		}
	})

	t.Run("empty url", func(t *testing.T) {
		c, err := NewCookieJarFile("cookie-jar")
		if err != nil {
			t.Error(err)
			return
		}

		c.SetCookies(new(url.URL), []*http.Cookie{{
			Name:   "empty-url",
			Value:  "aCookie",
			Path:   "/",
			Domain: "example.org",
		}})
		defer os.Remove(c.path)

		if len(c.siteCookies) > 0 {
			t.Errorf("unexpectedly stored a cookie with an empty url")
		}
	})

	t.Run("nil cookies", func(t *testing.T) {
		u, _ := url.Parse("https://example.org/")

		c, err := NewCookieJarFile("cookie-jar")
		if err != nil {
			t.Error(err)
			return
		}

		c.SetCookies(u, nil)
		defer os.Remove(c.path)

		if len(c.siteCookies) > 0 {
			t.Error("unexpectedly stored a nil cookie")
		}
	})

	t.Run("empty cookies", func(t *testing.T) {
		u, _ := url.Parse("https://example.org/")

		c, err := NewCookieJarFile("cookie-jar")
		if err != nil {
			t.Error(err)
			return
		}

		c.SetCookies(u, []*http.Cookie{})
		defer os.Remove(c.path)

		if len(c.siteCookies) > 0 {
			t.Error("unexpectedly stored an empty cookie")
		}
	})

	t.Run("bad scheme", func(t *testing.T) {
		u, _ := url.Parse("ftp://example.org")

		c, err := NewCookieJarFile("cookie-jar")
		if err != nil {
			t.Error(err)
			return
		}

		c.SetCookies(u, []*http.Cookie{{
			Name:   "bad-scheme",
			Value:  "aCookie",
			Path:   "/",
			Domain: "example.org",
		}})
		defer os.Remove(c.path)

		if len(c.siteCookies) > 0 {
			t.Error("unexpectedly stored an empty cookie")
		}
	})
}

func TestCookieJarFile_SetCookies(t *testing.T) {
	f := "test-cookies"
	u, _ := url.Parse("https://example.org")

	cookies := []*http.Cookie{
		{
			Name:   "cookie1",
			Value:  "value1",
			Path:   "/",
			Domain: u.Host,
		},
		{
			Name:   "cookie2",
			Value:  "value2",
			Path:   "/",
			Domain: u.Host,
		},
	}

	t.Run("store new", func(t *testing.T) {
		c, err := NewCookieJarFile(f)
		if err != nil {
			t.Error(err)
			return
		}
		defer os.Remove(c.path)

		c.SetCookies(u, cookies)
		if len(c.siteCookies) != 1 {
			t.Error("site cookie count mismatch")
		}

		if len(c.Cookies(u)) != len(cookies) {
			t.Error("cookie count mismatch")
		}

		// set new cookie
		c.SetCookies(u, []*http.Cookie{
			{
				Name:   "cookie3",
				Value:  "value3",
				Path:   "/",
				Domain: u.Host,
			},
		})

		// should still be 1, since it's in the same domain
		if len(c.siteCookies) != 1 {
			t.Error("site cookie count mismatch")
		}

		if len(c.Cookies(u)) != len(cookies)+1 {
			t.Error("cookie count mismatch")
		}

		u2, _ := url.Parse("http://example.com")
		c.SetCookies(u2, []*http.Cookie{
			{
				Name:   "other-cookie",
				Value:  "xx",
				Path:   "/",
				Domain: u2.Host,
			},
		})

		if len(c.siteCookies) != 2 {
			t.Error("site cookie count mismatch")
		}
	})
}

func TestCookieJarFile_LoadFile(t *testing.T) {
	f := "test-cookies"
	u1, _ := url.Parse("http://google.com")
	u2, _ := url.Parse("https://example.com")
	u3, _ := url.Parse("https://google.com")

	c, err := NewCookieJarFile(f)
	if err != nil {
		t.Error(err)
		return
	}
	defer os.Remove(f)

	c.SetCookies(u1, []*http.Cookie{
		{
			Name:   u1.String() + "-cookie1",
			Value:  "value1",
			Path:   "/",
			Domain: u1.Host,
		},
	})

	c.SetCookies(u2, []*http.Cookie{
		{
			Name:   u2.String() + "-cookie1",
			Value:  "value1",
			Path:   "/",
			Domain: u2.Host,
		},
		{
			Name:   u2.String() + "-cookie2",
			Value:  "value2",
			Path:   "/",
			Domain: u2.Host,
		},
	})

	c.SetCookies(u3, []*http.Cookie{
		{
			Name:   u3.String() + "-cookie1",
			Value:  "value1",
			Path:   "/",
			Domain: u3.Host,
		},
		{
			Name:   u3.String() + "-cookie2",
			Value:  "value2",
			Path:   "/",
			Domain: u3.Host,
		},
		{
			Name:   u3.String() + "-cookie3",
			Value:  "value3",
			Path:   "/",
			Domain: u3.Host,
		},
	})

	t.Run("test load", func(t *testing.T) {
		c1, err := NewCookieJarFile(f)
		if err != nil {
			t.Error(err)
			return
		}

		if len(c1.siteCookies) != 3 {
			t.Error("site cookie count mismatch")
		}

		// This will get cookies for all of google.com ... http or https
		if len(c1.Cookies(u1)) != 4 {
			t.Error("cookie count mismatch")
		}

		if len(c1.Cookies(u2)) != 2 {
			t.Error("cookie count mismatch")
		}
	})
}
