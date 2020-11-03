package cache

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCookieJar(t *testing.T) {
	t.Run("re-get", func(t *testing.T) {
		cj := CookieJar(os.DevNull)
		cj2 := CookieJar(os.DevNull)

		if !reflect.DeepEqual(cj, cj2) {
			t.Error("did not receive singleton")
		}
	})
}

func TestNewCookieJar(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		j, err := newCookieJar("x")
		if err != nil {
			t.Error(err)
			return
		}

		if j.path != "x" {
			t.Error("invalid cookie jar file")
			return
		}
	})

	t.Run("bad", func(t *testing.T) {
		if _, err := newCookieJar("//invalid/:mem:/^?"); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestCookieJar_SetCookies(t *testing.T) {
	j, err := newCookieJar(os.DevNull)
	if err != nil {
		t.Error(err)
		return
	}

	u, _ := url.Parse("https://example.org")
	c := []*http.Cookie{
		{
			Name:   "test1",
			Value:  "value1",
			Path:   "/",
			Domain: u.Hostname(),
		},
		{
			Name:   "test2",
			Value:  "value2",
			Path:   "/",
			Domain: u.Hostname(),
		},
		{
			Name:   "test3",
			Value:  "value3",
			Path:   "/",
			Domain: u.Hostname(),
		},
	}

	j.SetCookies(u, c)

	if len(j.Cookies(u)) != len(c) {
		t.Error("error setting cookies")
	}

	// add new cookie, same domain
	j.SetCookies(u, []*http.Cookie{{
		Name:   "test4",
		Value:  "value4",
		Path:   "/",
		Domain: u.Hostname(),
	}})

	if len(j.Cookies(u)) != len(c)+1 {
		t.Error("did not update cookies")
	}

	// add new cookie, new domain
	u2, _ := url.Parse("http://www.example.net")
	j.SetCookies(u2, []*http.Cookie{{
		Name:   "testA",
		Value:  "valueA",
		Path:   "/",
		Domain: u2.Hostname(),
	}})

	if len(j.Cookies(u)) != len(c)+1 || len(j.Cookies(u2)) != 1 {
		t.Error("invalid cookie update")
	}
}

func TestCookieJar_SetCookies_Errors(t *testing.T) {
	t.Run("all empty", func(t *testing.T) {
		c, err := newCookieJar(os.DevNull)
		if err != nil {
			t.Error(err)
			return
		}

		u := new(url.URL)
		c.SetCookies(u, []*http.Cookie{})
		if len(c.Cookies(u)) > 0 {
			t.Error("set cookie from empty data")
		}
	})

	t.Run("nil url", func(t *testing.T) {
		c, err := newCookieJar(os.DevNull)
		if err != nil {
			t.Error(err)
			return
		}

		c.SetCookies(nil, []*http.Cookie{})
		if len(c.Cookies(nil)) > 0 {
			t.Error("set cookie from empty data")
		}
	})

	t.Run("empty url", func(t *testing.T) {
		c, err := newCookieJar(os.DevNull)
		if err != nil {
			t.Error(err)
			return
		}

		u := new(url.URL)
		c.SetCookies(u, []*http.Cookie{{
			Name:   "testA",
			Value:  "valueA",
			Path:   "/",
			Domain: u.Hostname(),
		}})
		if len(c.Cookies(u)) > 0 {
			t.Error("set cookie from empty data")
		}
	})

	t.Run("nil cookies", func(t *testing.T) {
		c, err := newCookieJar(os.DevNull)
		if err != nil {
			t.Error(err)
			return
		}

		u, _ := url.Parse("http://example.org")
		c.SetCookies(u, nil)
		if len(c.Cookies(u)) > 0 {
			t.Error("set cookie from empty data")
		}
	})

	t.Run("empty cookies", func(t *testing.T) {
		c, err := newCookieJar(os.DevNull)
		if err != nil {
			t.Error(err)
			return
		}

		u, _ := url.Parse("http://example.org")
		c.SetCookies(u, []*http.Cookie{})
		if len(c.Cookies(u)) > 0 {
			t.Error("set cookie from empty data")
		}
	})

	t.Run("bad scheme", func(t *testing.T) {
		c, err := newCookieJar(os.DevNull)
		if err != nil {
			t.Error(err)
			return
		}

		u, _ := url.Parse("gopher://example.org")
		c.SetCookies(u, []*http.Cookie{{
			Name:   "testA",
			Value:  "valueA",
			Path:   "/",
			Domain: u.Hostname(),
		}})
		if len(c.Cookies(u)) > 0 {
			t.Error("set cookie from empty data")
		}
	})
}

func TestCookieJar_Cache(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		u, _ := url.Parse("https://example.org")
		c := []*http.Cookie{
			{
				Name:   "test1",
				Value:  "value1",
				Path:   "/",
				Domain: u.Hostname(),
			},
			{
				Name:   "test2",
				Value:  "value2",
				Path:   "/",
				Domain: u.Hostname(),
			},
			{
				Name:   "test3",
				Value:  "value3",
				Path:   "/",
				Domain: u.Hostname(),
			},
		}
		m := make(map[string][]*http.Cookie)
		m[fmt.Sprintf("%s://%s", u.Scheme, u.Hostname())] = c

		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}

		f := filepath.Join(t.TempDir(), "test.cookies")
		if err = ioutil.WriteFile(f, data, 0666|os.ModeExclusive); err != nil {
			t.Fatal(err)
		}

		cj, err := newCookieJar(f)
		if err != nil {
			t.Error(err)
			return
		}

		if len(cj.Cookies(u)) != len(c) {
			t.Error("incorrect cache state")
		}
	})

	t.Run("invalid data", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "test.cookies")
		if err := ioutil.WriteFile(f, []byte("something, but not right"), 0666|os.ModeExclusive); err != nil {
			t.Fatal(err)
		}

		if _, err := newCookieJar(f); err != nil {
			t.Error(err)
			return
		}
	})
}
