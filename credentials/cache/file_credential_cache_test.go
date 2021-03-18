/*
 * Copyright (c) 2021 Michael Morris. All Rights Reserved.
 *
 * Licensed under the MIT license (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * https://github.com/mmmorris1975/aws-runas/blob/master/LICENSE
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under the License.
 */

package cache

import (
	"github.com/mmmorris1975/aws-runas/credentials"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileCredentialCache_Store(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		creds := &credentials.Credentials{
			AccessKeyId:     "mock",
			SecretAccessKey: "mock",
			Expiration:      time.Now(),
		}

		f := filepath.Join(t.TempDir(), "cache")
		c := NewFileCredentialCache(f)
		if err := c.Store(creds); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("empty", func(t *testing.T) {
		c := NewFileCredentialCache(os.DevNull)
		if err := c.Store(&credentials.Credentials{}); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("nil", func(t *testing.T) {
		c := NewFileCredentialCache(os.DevNull)
		if err := c.Store(nil); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("bad path", func(t *testing.T) {
		cred := &credentials.Credentials{
			AccessKeyId:     "TestAK",
			SecretAccessKey: "TestSK",
		}

		c := NewFileCredentialCache("//invalid/:mem:/^?")
		if err := c.Store(cred); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestFileCredentialCache_Load(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		cred := &credentials.Credentials{
			AccessKeyId:     "AKIAM0CK",
			SecretAccessKey: "secretKey",
			Token:           "sessionToken",
			Expiration:      time.Now().Add(1 * time.Hour),
		}

		f := filepath.Join(t.TempDir(), "cache")
		c := NewFileCredentialCache(f)
		if err := c.Store(cred); err != nil {
			t.Error(err)
			return
		}

		cr := c.Load()

		if cr.AccessKeyId != cred.AccessKeyId || cr.SecretAccessKey != cred.SecretAccessKey ||
			cr.Token != cred.Token || cr.Expiration.Unix() != cred.Expiration.Unix() {
			t.Error("data mismatch")
		}
	})

	t.Run("bad file", func(t *testing.T) {
		c := NewFileCredentialCache("this-is-not-a-file")
		if cr := c.Load(); cr.Value().HasKeys() {
			t.Error("did not receive empty credentials")
			return
		}
	})

	t.Run("empty file", func(t *testing.T) {
		c := NewFileCredentialCache(os.DevNull)
		if cr := c.Load(); cr.Value().HasKeys() {
			t.Error("did not receive empty credentials")
			return
		}
	})

	t.Run("bad json key", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "cache")
		c := NewFileCredentialCache(f)

		j := `{"AccessKeyId": "akid", "SecretAccessKeyID": "sak"}`
		if err := os.WriteFile(c.path, []byte(j), 0600); err != nil {
			t.Error(err)
			return
		}

		if cr := c.Load(); cr.Value().HasKeys() {
			t.Error("did not receive empty credentials")
		}
	})

	t.Run("bad json value", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "cache")
		c := NewFileCredentialCache(f)

		j := `{"AccessKeyId": "akid", "SecretAccessKey": "sak", "Expiration": 0}`
		if err := os.WriteFile(c.path, []byte(j), 0600); err != nil {
			t.Error(err)
			return
		}

		if cr := c.Load(); cr.Value().HasKeys() {
			t.Error("did not receive empty credentials")
		}
	})
}

func TestFileCredentialCache_Clear(t *testing.T) {
	f := filepath.Join(t.TempDir(), "cache")
	if err := NewFileCredentialCache(f).Clear(); err != nil {
		t.Error(err)
		return
	}
}
