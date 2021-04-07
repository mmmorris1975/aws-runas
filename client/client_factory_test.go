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
	"github.com/mmmorris1975/aws-runas/config"
	"testing"
)

func TestClientFactory_Get(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		if _, err := NewClientFactory(new(mockResolver), DefaultOptions).Get(nil); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		cfg := &config.AwsConfig{
			SamlUrl:        "http://localhost/saml",
			WebIdentityUrl: "http://localhost/",
		}

		if _, err := NewClientFactory(new(mockResolver), DefaultOptions).Get(cfg); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("arn profile", func(t *testing.T) {
		cfg := &config.AwsConfig{ProfileName: "arn:aws:iam::01234567890:role/Admin"}
		c, err := NewClientFactory(new(mockResolver), DefaultOptions).Get(cfg)
		if err != nil {
			t.Error("error")
		}

		if c == nil {
			t.Fatal("nil client")
		}

		if _, ok := c.(*assumeRoleClient); !ok {
			t.Error("invalid client type")
		}
	})
}

func TestClientFactory_Get_Saml(t *testing.T) {
	t.Run("with jump role", func(t *testing.T) {
		cfg, err := new(mockResolver).Config("SamlJump")
		if err != nil {
			t.Fatal(err)
		}

		c, err := NewClientFactory(new(mockResolver), DefaultOptions).Get(cfg)
		if err != nil {
			t.Fatal(err)
		}

		if c == nil {
			t.Fatal("nil config")
		}

		// this will be an assumeRoleClient wrapping a samlRoleClient
		if _, ok := c.(*assumeRoleClient); !ok {
			t.Error("invalid client type")
		}
	})

	t.Run("no jump role", func(t *testing.T) {
		cfg, err := new(mockResolver).Config("Saml")
		if err != nil {
			t.Fatal(err)
		}

		c, err := NewClientFactory(new(mockResolver), DefaultOptions).Get(cfg)
		if err != nil {
			t.Fatal(err)
		}

		if c == nil {
			t.Fatal("nil config")
		}

		if _, ok := c.(*samlRoleClient); !ok {
			t.Error("invalid client type")
		}
	})

	t.Run("bad saml credentials", func(t *testing.T) {
		r := mockResolver(true)
		cfg, err := r.Config("Saml")
		if err != nil {
			t.Fatal(err)
		}

		// will return empty credentials, and no error
		c, err := NewClientFactory(&r, DefaultOptions).Get(cfg)

		if err != nil {
			t.Fatal(err)
		}

		// error will be here
		if _, err = c.Credentials(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestClientFactory_Get_Web(t *testing.T) {
	t.Run("with jump role", func(t *testing.T) {
		cfg, err := new(mockResolver).Config("WebJump")
		if err != nil {
			t.Fatal(err)
		}

		c, err := NewClientFactory(new(mockResolver), DefaultOptions).Get(cfg)
		if err != nil {
			t.Fatal(err)
		}

		if c == nil {
			t.Fatal("nil config")
		}

		// this will be an assumeRoleClient wrapping a webRoleClient
		if _, ok := c.(*assumeRoleClient); !ok {
			t.Error("invalid client type")
		}
	})

	t.Run("no jump role", func(t *testing.T) {
		cfg, err := new(mockResolver).Config("Web")
		if err != nil {
			t.Fatal(err)
		}

		c, err := NewClientFactory(new(mockResolver), DefaultOptions).Get(cfg)
		if err != nil {
			t.Fatal(err)
		}

		if c == nil {
			t.Fatal("nil config")
		}

		if _, ok := c.(*webRoleClient); !ok {
			t.Error("invalid client type")
		}
	})

	t.Run("bad web credentials", func(t *testing.T) {
		r := mockResolver(true)
		cfg, err := r.Config("Web")
		if err != nil {
			t.Fatal(err)
		}

		// will return empty credentials, and no error
		c, err := NewClientFactory(&r, DefaultOptions).Get(cfg)

		if err != nil {
			t.Fatal(err)
		}

		// error will be here
		if _, err = c.Credentials(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestClientFactory_Get_IamRole(t *testing.T) {
	t.Run("with session client", func(t *testing.T) {
		cfg, err := new(mockResolver).Config("IamRoleSession")
		if err != nil {
			t.Fatal(err)
		}

		c, err := NewClientFactory(new(mockResolver), DefaultOptions).Get(cfg)
		if err != nil {
			t.Fatal(err)
		}

		if c == nil {
			t.Fatal("nil config")
		}

		if _, ok := c.(*assumeRoleClient); !ok {
			// we're unable to inspect deeper in the client, since this is a generic interface type
			t.Error("invalid client type")
		}
	})

	t.Run("no session client", func(t *testing.T) {
		cfg, err := new(mockResolver).Config("IamRole")
		if err != nil {
			t.Fatal(err)
		}

		c, err := NewClientFactory(new(mockResolver), DefaultOptions).Get(cfg)
		if err != nil {
			t.Fatal(err)
		}

		if c == nil {
			t.Fatal("nil config")
		}

		if _, ok := c.(*assumeRoleClient); !ok {
			// we're unable to inspect deeper in the client, since this is a generic interface type
			t.Error("invalid client type")
		}
	})
}

func TestClientFactory_Get_IamSession(t *testing.T) {
	cfg, err := new(mockResolver).Config("session")
	if err != nil {
		t.Fatal(err)
	}

	c, err := NewClientFactory(new(mockResolver), DefaultOptions).Get(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if c == nil {
		t.Fatal("nil config")
	}

	if _, ok := c.(*sessionTokenClient); !ok {
		t.Error("invalid client type")
	}
}
