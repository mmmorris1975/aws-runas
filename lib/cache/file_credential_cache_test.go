package cache

import (
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestFileCredentialCache_Store(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := &FileCredentialCache{Path: os.DevNull}
		if err := c.Store(&CacheableCredentials{Expiration: time.Now().Unix()}); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("nil-cred", func(t *testing.T) {
		c := &FileCredentialCache{Path: os.DevNull}
		if err := c.Store(nil); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("io error", func(t *testing.T) {
		c := &FileCredentialCache{Path: string(os.PathSeparator)}
		if err := c.Store(&CacheableCredentials{Expiration: time.Now().Unix()}); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestFileCredentialCache_Fetch(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		f := ".cred-cache"

		cred := &CacheableCredentials{
			Expiration: 12345,
		}
		cred.AccessKeyID = "AKIAM0CK"
		cred.SecretAccessKey = "s3cReTK3Y"
		cred.SessionToken = "SomethingWitty"
		cred.ProviderName = "MockProvider"

		c := &FileCredentialCache{Path: f}
		if err := c.Store(cred); err != nil {
			t.Error(err)
			return
		}

		r, err := c.Fetch()
		if err != nil {
			t.Error(err)
			return
		}
		// put defer here, in case we need to troubleshoot the file contents
		defer os.Remove(f)

		if r.AccessKeyID != cred.AccessKeyID {
			t.Error("access key mismatch")
			return
		}

		if r.SecretAccessKey != cred.SecretAccessKey {
			t.Error("secret key mismatch")
		}

		if r.SessionToken != cred.SessionToken {
			t.Error("session token mismatch")
		}

		if r.Expiration != cred.Expiration {
			t.Error("expiration mismatch")
		}
	})

	t.Run("no file", func(t *testing.T) {
		c := FileCredentialCache{Path: "this-is-not-a-file"}
		if _, err := c.Fetch(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("bad json key", func(t *testing.T) {
		// bad key will do Fetch() successfully, will be ignored
		f := ".cred-cache"
		j := `{"AccessKeyID": "akid", "SecretAccessKeyID": "sak", "Expiration": 0}`
		if err := ioutil.WriteFile(f, []byte(j), 0600); err != nil {
			t.Error(err)
			return
		}
		defer os.Remove(f)

		c := &FileCredentialCache{Path: f}

		r, err := c.Fetch()
		if err != nil {
			t.Error(err)
			return
		}

		if r.AccessKeyID != "akid" {
			t.Error("access key mismatch")
		}

		if r.SecretAccessKey != "" {
			t.Error("did not receive empty secret key")
		}
	})

	t.Run("bad json value", func(t *testing.T) {
		f := ".cred-cache"
		j := `{"AccessKeyID": 12345, "SecretAccessKey": 54321, "Expiration": "abcde"}`
		if err := ioutil.WriteFile(f, []byte(j), 0600); err != nil {
			t.Error(err)
			return
		}
		defer os.Remove(f)

		c := &FileCredentialCache{Path: f}
		if _, err := c.Fetch(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}
