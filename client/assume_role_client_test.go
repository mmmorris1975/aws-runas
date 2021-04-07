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

package client

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/mmmorris1975/aws-runas/credentials"
	"os"
	"testing"
)

func TestNewAssumeRoleClient(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := NewAssumeRoleClient(aws.Config{}, &AssumeRoleClientConfig{RoleSessionName: "mockSessionName"})
		if c == nil || c.creds == nil || c.ident == nil {
			t.Error("invalid client")
			return
		}
	})

	t.Run("nil client config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewAssumeRoleProvider with nil config")
			}
		}()
		NewAssumeRoleClient(aws.Config{}, nil)
	})

	t.Run("empty client config", func(t *testing.T) {
		// avoid reaching out to aws for identity with unset RoleSessionName
		_ = os.Setenv("AWS_SHARED_CREDENTIALS_FILE", os.DevNull)
		for _, e := range []string{"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY"} {
			os.Unsetenv(e)
		}

		c := NewAssumeRoleClient(aws.Config{}, new(AssumeRoleClientConfig))
		if c == nil {
			t.Error("nil client")
			return
		}
	})
}

func TestAssumeRoleClient_Identity(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		id, err := newAssumeRoleClient().Identity()
		if err != nil {
			t.Error(err)
			return
		}

		if id.Username != "mockUser" || id.IdentityType != "user" || id.Provider != "MockIdentityProvider" {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("error", func(t *testing.T) {
		c := newAssumeRoleClient()
		c.ident = &mockIdent{true}

		if _, err := c.Identity(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestAssumeRoleClient_Roles(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		roles, err := newAssumeRoleClient().Roles()
		if err != nil {
			t.Error(err)
			return
		}

		if len(*roles) < 2 {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("error", func(t *testing.T) {
		c := newAssumeRoleClient()
		c.ident = &mockIdent{true}

		if _, err := c.Roles(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestAssumeRoleClient_Credentials(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		creds, err := newAssumeRoleClient().Credentials()
		if err != nil {
			t.Error(err)
			return
		}

		if creds.AccessKeyId != "mockAK" || creds.SecretAccessKey != "mockSK" || creds.Token != "mockST" {
			t.Error("data mismatch")
			return
		}
	})

	t.Run("error", func(t *testing.T) {
		c := newAssumeRoleClient()
		c.creds = aws.NewCredentialsCache(&mockCredProvider{sendError: true})

		if _, err := c.Credentials(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestAssumeRoleClient_ConfigProvider(t *testing.T) {
	c := newAssumeRoleClient()
	c.session = aws.Config{}
	if cp := c.ConfigProvider(); cp.Region != c.session.Region {
		t.Error("invalid config provider")
	}
}

func TestAssumeRoleClient_ClearCache(t *testing.T) {
	c := newAssumeRoleClient()
	c.provider = credentials.NewAssumeRoleProvider(aws.Config{}, "mockRole")

	t.Run("no cache", func(t *testing.T) {
		c.provider.Cache = nil
		if err := c.ClearCache(); err != nil {
			t.Error(err)
		}
	})

	t.Run("with cache", func(t *testing.T) {
		c.provider.Cache = &memCredCache{
			creds: &credentials.Credentials{
				AccessKeyId:     "mockAk",
				SecretAccessKey: "mockSk",
				Token:           "mockToken",
			},
		}

		if err := c.ClearCache(); err != nil {
			t.Error(err)
			return
		}

		if !c.provider.Cache.Load().Expiration.IsZero() {
			t.Error("invalid cache state")
		}
	})
}

func newAssumeRoleClient() *assumeRoleClient {
	c := &assumeRoleClient{baseIamClient: new(baseIamClient)}
	c.creds = aws.NewCredentialsCache(new(mockCredProvider))
	c.ident = new(mockIdent)
	return c
}
