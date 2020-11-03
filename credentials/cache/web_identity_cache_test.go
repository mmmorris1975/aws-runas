package cache

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/mmmorris1975/aws-runas/credentials"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestWebIdentityCache(t *testing.T) {
	t.Run("re-get", func(t *testing.T) {
		c1 := WebIdentityCache(os.DevNull)
		c2 := WebIdentityCache(os.DevNull)

		if !reflect.DeepEqual(c1, c2) {
			t.Error("did not receive singleton")
		}
	})
}

func TestNewWebIdentityCache(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		j, err := newWebIdentityCache("x")
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
		if _, err := newWebIdentityCache("//invalid/:mem:/^?"); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestWebIdentityCache_Store(t *testing.T) {
	f := filepath.Join(t.TempDir(), "cache")
	c, err := newWebIdentityCache(f)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("good", func(t *testing.T) {
		tok := credentials.OidcIdentityToken("mockValue")

		if err = c.Store("mockKey", &tok); err != nil {
			t.Error(err)
			return
		}

		if len(c.cache) != 1 {
			t.Error("invalid cache found")
		}

		if c.cache[tokenCacheKey("mockKey")].String() != tok.String() {
			t.Error("data mismatch")
		}
	})

	t.Run("empty url", func(t *testing.T) {
		if err := c.Store("", new(credentials.OidcIdentityToken)); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("empty token", func(t *testing.T) {
		if err := c.Store("url", new(credentials.OidcIdentityToken)); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("nil token", func(t *testing.T) {
		if err := c.Store("url", nil); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestWebIdentityCache_Cache(t *testing.T) {
	t.Run("good", func(t *testing.T) {

	})

	t.Run("bad data", func(t *testing.T) {
		f, err := os.Create(filepath.Join(t.TempDir(), "cache"))
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = f.Write([]byte("test"))
		_ = f.Close()

		c, err := newWebIdentityCache(f.Name())
		if err != nil {
			t.Error(err)
			return
		}

		if len(c.cache) > 0 {
			t.Error("unexpected data found in cache")
		}
	})
}

func TestWebIdentityCache_Load(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		ex := map[string]interface{}{"exp": time.Now().Add(1 * time.Hour).UTC().Unix()}
		j, _ := json.Marshal(ex)
		rawTok := fmt.Sprintf("mock.%s.mock", base64.RawURLEncoding.EncodeToString(j))
		tok := credentials.OidcIdentityToken(rawTok)

		c, _ := newWebIdentityCache(os.DevNull)
		c.cache[tokenCacheKey("mock")] = &tok

		v := c.Load("mock")

		if v == nil {
			t.Error("received unexpected invalid token")
			return
		}

		if v.String() != rawTok {
			t.Error("data mismatch")
		}
	})

	t.Run("expired", func(t *testing.T) {
		ex := map[string]interface{}{"exp": time.Now().Add(-1 * time.Second).UTC().Unix()}
		j, _ := json.Marshal(ex)
		rawTok := fmt.Sprintf("mock.%s.mock", base64.RawURLEncoding.EncodeToString(j))
		tok := credentials.OidcIdentityToken(rawTok)

		c, _ := newWebIdentityCache(os.DevNull)
		c.cache[tokenCacheKey("mock")] = &tok

		if v := c.Load("mock"); v != nil {
			t.Error("received unexpected valid token")
		}
	})

	t.Run("missing", func(t *testing.T) {
		c, _ := newWebIdentityCache(os.DevNull)
		if tok := c.Load("invalid"); tok != nil {
			t.Error("received unexpected valid token")
		}
	})
}

func TestWebIdentityCache_Clear(t *testing.T) {
	f := filepath.Join(t.TempDir(), "cache")
	c, _ := newWebIdentityCache(f)
	if err := c.Clear(); err != nil {
		t.Error(err)
		return
	}
}
