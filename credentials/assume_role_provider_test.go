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

package credentials

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/mmmorris1975/aws-runas/shared"
	"testing"
	"time"
)

func TestNewAssumeRoleProvider(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		p := newAssumeRoleProvider()

		if p.Client == nil {
			t.Error("invalid Client")
		}

		if p.Duration != AssumeRoleDurationDefault {
			t.Error("invalid default duration")
		}

		if p.Logger == nil {
			t.Error("invalid default logger")
		}

		if p.TokenProvider == nil {
			t.Error("invalid default token provider")
		}
	})
}

func TestAssumeRoleProvider_Retrieve(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		p := newAssumeRoleProvider()

		v, err := p.Retrieve(context.Background())
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.Source != AssumeRoleProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("zero duration", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.Duration = 0 * time.Second

		v, err := p.Retrieve(context.Background())
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.Source != AssumeRoleProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("short duration", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.Duration = 1 * time.Second

		v, err := p.Retrieve(context.Background())
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.Source != AssumeRoleProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("long duration", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.Duration = 100 * time.Hour

		v, err := p.Retrieve(context.Background())
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.Source != AssumeRoleProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("invalid role arn", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.RoleArn = ""

		_, err := p.Retrieve(context.Background())
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("invalid role session name", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.RoleSessionName = ""

		_, err := p.Retrieve(context.Background())
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestAssumeRoleProvider_Retrieve_Mfa(t *testing.T) {
	t.Run("good code", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.SerialNumber = "mfa"
		p.TokenCode = "123456"

		v, err := p.Retrieve(context.Background())
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.Source != AssumeRoleProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("bad code", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.SerialNumber = "mfa"
		p.TokenCode = "abcdef"

		_, err := p.Retrieve(context.Background())
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("prompt", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.SerialNumber = "mfa"
		p.TokenProvider = func() (string, error) {
			return "123456", nil
		}

		v, err := p.Retrieve(context.Background())
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.Source != AssumeRoleProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("nil provider", func(t *testing.T) {
		p := newAssumeRoleProvider()
		p.SerialNumber = "mfa"
		p.TokenProvider = nil

		_, err := p.Retrieve(context.Background())
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestAssumeRoleProvider_Retrieve_Cache(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := &memCredCache{
			creds: &Credentials{
				AccessKeyId:     "AKcached",
				SecretAccessKey: "SKcached",
				Token:           "STcached",
				Expiration:      time.Now().Add(6 * time.Hour),
			},
		}
		p := newAssumeRoleProvider()
		p.Cache = c

		v, err := p.Retrieve(context.Background())
		if err != nil {
			t.Error(err)
			return
		}

		if v.AccessKeyID != "AKcached" || v.SecretAccessKey != "SKcached" || v.SessionToken != "STcached" {
			t.Error("credential mismatch")
			return
		}
	})

	t.Run("expired", func(t *testing.T) {
		c := &memCredCache{
			creds: &Credentials{
				AccessKeyId:     "AKcached",
				SecretAccessKey: "SKcached",
				Token:           "STcached",
				Expiration:      time.Now().Add(-6 * time.Hour),
			},
		}
		p := newAssumeRoleProvider()
		p.Cache = c

		v, err := p.Retrieve(context.Background())
		if err != nil {
			t.Error(err)
			return
		}

		if v.AccessKeyID == "AKcached" || v.SecretAccessKey == "SKcached" || v.SessionToken == "STcached" {
			t.Error("unexpected credential match")
			return
		}
	})
}

func newAssumeRoleProvider() *AssumeRoleProvider {
	p := NewAssumeRoleProvider(aws.Config{}, "mockRole")
	p.Client = new(stsMock)
	p.RoleSessionName = "mySession"
	p.Logger = new(shared.DefaultLogger)
	return p
}
