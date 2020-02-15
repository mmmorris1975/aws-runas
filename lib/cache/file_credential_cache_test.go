package cache

import (
	"github.com/aws/aws-sdk-go/aws"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestFileCredentialCache_Store(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := NewFileCredentialCache(os.DevNull)
		if err := c.Store(&CacheableCredentials{}); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("nil-cred", func(t *testing.T) {
		c := NewFileCredentialCache(os.DevNull)
		if err := c.Store(nil); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("io error", func(t *testing.T) {
		c := NewFileCredentialCache(string(os.PathSeparator))
		if err := c.Store(&CacheableCredentials{}); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestFileCredentialCache_Load(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		cred := &CacheableCredentials{
			AccessKeyId:     aws.String("AKIAM0CK"),
			SecretAccessKey: aws.String("secretKey"),
			SessionToken:    aws.String("sessionToken"),
			Expiration:      aws.Time(time.Now().Add(1 * time.Hour)),
		}

		c := NewFileCredentialCache(".cred-cache")
		if err := c.Store(cred); err != nil {
			t.Error(err)
			return
		}

		cr, err := c.Load()
		if err != nil {
			t.Error(err)
			return
		}
		// put defer here, in case we need to troubleshoot the file contents
		defer os.Remove(c.path)

		if *cr.AccessKeyId != *cred.AccessKeyId || *cr.SecretAccessKey != *cred.SecretAccessKey ||
			*cr.SessionToken != *cred.SessionToken || cr.Expiration.Unix() != cred.Expiration.Unix() {
			t.Error("data mismatch")
		}
	})

	t.Run("no file", func(t *testing.T) {
		c := NewFileCredentialCache("this-is-not-a-file")
		if _, err := c.Load(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("bad json key", func(t *testing.T) {
		c := NewFileCredentialCache(".cred-cache")

		j := `{"AccessKeyId": "akid", "SecretAccessKeyID": "sak"}`
		if err := ioutil.WriteFile(c.path, []byte(j), 0600); err != nil {
			t.Error(err)
			return
		}
		defer os.Remove(c.path)

		r, err := c.Load()
		if err != nil {
			t.Error(err)
			return
		}

		if *r.AccessKeyId != "akid" {
			t.Error("access key mismatch")
		}

		if r.SecretAccessKey != nil {
			t.Error("did not receive empty secret key")
		}
	})

	t.Run("bad json value", func(t *testing.T) {
		c := NewFileCredentialCache(".cred-cache")

		j := `{"AccessKeyId": "akid", "SecretAccessKey": "sak", "Expiration": 0}`
		if err := ioutil.WriteFile(c.path, []byte(j), 0600); err != nil {
			t.Error(err)
			return
		}
		defer os.Remove(c.path)

		if _, err := c.Load(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}
