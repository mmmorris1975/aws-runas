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

func TestNewWebRoleProvider(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		p := newWebRoleProvider()

		if p.Client == nil {
			t.Error("invalid Client")
		}

		if p.Duration != AssumeRoleDurationDefault {
			t.Error("invalid default duration")
		}

		if p.Logger == nil {
			t.Error("invalid default logger")
		}
	})

	t.Run("session options", func(t *testing.T) {
		p := NewWebRoleProvider(aws.Config{}, "")

		if p.Client == nil {
			t.Error("invalid Client")
		}

		if p.Duration != AssumeRoleDurationDefault {
			t.Error("invalid default duration")
		}

		if p.Logger == nil {
			t.Error("invalid default logger")
		}
	})
}

func TestWebRoleProvider_Retrieve(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		p := newWebRoleProvider()

		v, err := p.Retrieve(context.Background())
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.Source != WebRoleProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("zero duration", func(t *testing.T) {
		p := newWebRoleProvider()
		p.Duration = 0 * time.Second

		v, err := p.Retrieve(context.Background())
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.Source != WebRoleProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("short duration", func(t *testing.T) {
		p := newWebRoleProvider()
		p.Duration = 1 * time.Second

		v, err := p.Retrieve(context.Background())
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.Source != WebRoleProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("long duration", func(t *testing.T) {
		p := newWebRoleProvider()
		p.Duration = 100 * time.Hour

		v, err := p.Retrieve(context.Background())
		if err != nil {
			t.Error(err)
			return
		}

		if !v.HasKeys() || len(v.SessionToken) < 1 || v.Source != WebRoleProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("invalid role arn", func(t *testing.T) {
		p := newWebRoleProvider()
		p.RoleArn = ""

		_, err := p.Retrieve(context.Background())
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("invalid role session name", func(t *testing.T) {
		p := newWebRoleProvider()
		p.RoleSessionName = ""

		_, err := p.Retrieve(context.Background())
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		p := newWebRoleProvider()
		p.webIdentityToken = new(OidcIdentityToken)

		_, err := p.Retrieve(context.Background())
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestWebRoleProvider_Retrieve_Cache(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := &memCredCache{
			creds: &Credentials{
				AccessKeyId:     "AKcached",
				SecretAccessKey: "SKcached",
				Token:           "STcached",
				Expiration:      time.Now().Add(6 * time.Hour),
			},
		}
		p := newWebRoleProvider()
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
		p := newWebRoleProvider()
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

func TestWebRoleProvider_ClearCache(t *testing.T) {
	p := newWebRoleProvider()

	t.Run("no cache", func(t *testing.T) {
		p.Cache = nil
		if err := p.ClearCache(); err != nil {
			t.Error(err)
		}
	})

	t.Run("with cache", func(t *testing.T) {
		p.Cache = &memCredCache{
			creds: &Credentials{
				AccessKeyId:     "AKcached",
				SecretAccessKey: "SKcached",
				Token:           "STcached",
				Expiration:      time.Now().Add(-6 * time.Hour),
			},
		}

		if err := p.ClearCache(); err != nil {
			t.Error(err)
			return
		}

		if !p.Cache.Load().Expiration.IsZero() {
			t.Error("cache was not cleared")
		}
	})
}

func newWebRoleProvider() *webRoleProvider {
	p := NewWebRoleProvider(aws.Config{}, "mockRole")
	p.Client = new(stsMock)
	p.RoleSessionName = "mySession"
	p.Logger = new(shared.DefaultLogger)

	t := OidcIdentityToken("mockToken")
	p.webIdentityToken = &t
	return p
}
