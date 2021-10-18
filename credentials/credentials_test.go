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
	"bytes"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"testing"
	"time"
)

func TestCredentials_CredentialsProcess(t *testing.T) {
	c := Credentials{
		AccessKeyId:     "mockAK",
		SecretAccessKey: "mockSK",
		Token:           "mockToken",
	}

	t.Run("expiring", func(t *testing.T) {
		c.Expiration = time.Now().Add(1 * time.Hour).UTC()
		defer func() { c.Expiration = time.Time{} }()

		j, err := c.CredentialsProcess()
		if err != nil {
			t.Error(err)
			return
		}

		if !matches(j, `"AccessKeyId"`, `"SecretAccessKey"`, `"SessionToken"`, `"Version"`, `"Expiration"`) {
			t.Error("invalid credentials")
		}
	})

	t.Run("non-expiring with token", func(t *testing.T) {
		j, err := c.CredentialsProcess()
		if err != nil {
			t.Error(err)
			return
		}

		if !matches(j, `"AccessKeyId"`, `"SecretAccessKey"`, `"SessionToken"`, `"Version"`) {
			t.Error("invalid credentials")
		}

		if matches(j, `"Expiration"`) {
			t.Error("invalid credentials")
		}
	})

	t.Run("non-expiring no token", func(t *testing.T) {
		c.Token = ""

		j, err := c.CredentialsProcess()
		if err != nil {
			t.Error(err)
			return
		}
		t.Logf("%s", j)

		if !matches(j, `"AccessKeyId"`, `"SecretAccessKey"`, `"Version"`) {
			t.Error("invalid credentials")
		}

		if matches(j, `"SessionToken"`, `"Expiration"`) {
			t.Error("invalid credentials")
		}
	})
}

func TestCredentials_EC2(t *testing.T) {
	c := Credentials{
		AccessKeyId:     "mockAK",
		SecretAccessKey: "mockSK",
		Token:           "mockToken",
		ProviderName:    "mockProvider",
	}

	t.Run("valid", func(t *testing.T) {
		c.Expiration = time.Now().Add(1 * time.Hour).UTC()

		j, err := c.EC2()
		if err != nil {
			t.Error(err)
			return
		}

		if !matches(j, `"AccessKeyId"`, `"SecretAccessKey"`, `"Token"`, `"Expiration"`, `"Code"`,
			`"Type"`, `"LastUpdated"`) {
			t.Error("invalid credentials")
		}

		if matches(j, `"ProviderName"`) {
			t.Error("invalid credentials")
		}
	})

	t.Run("expired", func(t *testing.T) {
		c.Expiration = time.Time{}

		j, err := c.EC2()
		if err != nil {
			t.Error(err)
			return
		}

		if !matches(j, `"AccessKeyId"`, `"SecretAccessKey"`, `"Token"`, `"Expiration"`, `"Code"`,
			`"Type"`, `"LastUpdated"`) {
			t.Error("invalid credentials")
		}

		if matches(j, `"ProviderName"`) {
			t.Error("invalid credentials")
		}
	})
}

func TestCredentials_ECS(t *testing.T) {
	c := Credentials{
		AccessKeyId:     "mockAK",
		SecretAccessKey: "mockSK",
		Token:           "mockToken",
		ProviderName:    "mockProvider",
	}

	t.Run("valid", func(t *testing.T) {
		c.Expiration = time.Now().Add(1 * time.Hour).UTC()

		j, err := c.ECS()
		if err != nil {
			t.Error(err)
			return
		}

		if !matches(j, `"AccessKeyId"`, `"SecretAccessKey"`, `"Token"`, `"Expiration"`) {
			t.Error("invalid credentials")
		}

		if matches(j, `"Code"`, `"Type"`, `"LastUpdated"`, `"ProviderName"`) {
			t.Error("invalid credentials")
		}
	})

	t.Run("expired", func(t *testing.T) {
		c.Expiration = time.Time{}

		j, err := c.ECS()
		if err != nil {
			t.Error(err)
			return
		}

		if !matches(j, `"AccessKeyId"`, `"SecretAccessKey"`, `"Token"`, `"Expiration"`) {
			t.Error("invalid credentials")
		}

		if matches(j, `"Code"`, `"Type"`, `"LastUpdated"`, `"ProviderName"`) {
			t.Error("invalid credentials")
		}
	})
}

func TestCredentials_Env(t *testing.T) {
	c := Credentials{
		AccessKeyId:     "mockAK",
		SecretAccessKey: "mockSK",
	}

	t.Run("with token", func(t *testing.T) {
		c.Token = "mockToken"
		defer func() { c.Token = "" }()

		m := c.Env()
		if m["AWS_ACCESS_KEY_ID"] != c.AccessKeyId || m["AWS_SECRET_ACCESS_KEY"] != c.SecretAccessKey ||
			m["AWS_SESSION_TOKEN"] != c.Token || m["AWS_SECURITY_TOKEN"] != c.Token {
			t.Error("invalid credentials")
		}
	})

	t.Run("no token", func(t *testing.T) {
		m := c.Env()
		if m["AWS_ACCESS_KEY_ID"] != c.AccessKeyId || m["AWS_SECRET_ACCESS_KEY"] != c.SecretAccessKey ||
			m["AWS_SESSION_TOKEN"] != "" || m["AWS_SECURITY_TOKEN"] != "" {
			t.Error("invalid credentials")
		}

		for k := range m {
			if k == "AWS_SESSION_TOKEN" {
				t.Error("invalid credentials")
			}
		}
	})
}

func TestCredentials_Value(t *testing.T) {
	c := Credentials{
		AccessKeyId:     "mockAK",
		SecretAccessKey: "mockSk",
		ProviderName:    "mockCredentials",
	}

	t.Run("with token", func(t *testing.T) {
		c.Token = "mockToken"
		defer func() { c.Token = "" }()

		v := c.Value()
		if !v.HasKeys() || v.AccessKeyID != c.AccessKeyId || v.SecretAccessKey != c.SecretAccessKey ||
			v.SessionToken != c.Token || v.Source != c.ProviderName {
			t.Error("invalid credentials")
		}
	})

	t.Run("no token", func(t *testing.T) {
		v := c.Value()
		if !v.HasKeys() || v.AccessKeyID != c.AccessKeyId || v.SecretAccessKey != c.SecretAccessKey ||
			v.SessionToken != "" || v.Source != c.ProviderName {
			t.Error("invalid credentials")
		}
	})
}

func TestCredentials_StsCredentials(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c := &Credentials{
			AccessKeyId:     "mockAK",
			SecretAccessKey: "mockSK",
			Token:           "mockToken",
			Expiration:      time.Unix(12345, 0),
		}

		v := c.StsCredentials()

		if v == nil {
			t.Error("nil credentials")
			return
		}

		if *v.AccessKeyId != c.AccessKeyId || *v.SecretAccessKey != c.SecretAccessKey || *v.SessionToken != c.Token {
			t.Error("data mismatch")
		}

		if v.Expiration.Unix() != 12345 {
			t.Error("expiration time mismatch")
		}
	})

	t.Run("empty", func(t *testing.T) {
		v := new(Credentials).StsCredentials()

		if v == nil {
			t.Error("nil credentials")
			return
		}

		// fields will be zero val, not nil
		if *v.AccessKeyId != "" || *v.SecretAccessKey != "" || *v.SessionToken != "" || !v.Expiration.IsZero() {
			t.Error("data mismatch")
		}
	})
}

func TestCredentials_FromValue(t *testing.T) {
	v := aws.Credentials{
		AccessKeyID:     "mockAK",
		SecretAccessKey: "mockSK",
		SessionToken:    "mockToken",
		Source:          "mockProvider",
	}

	c := FromValue(v)

	if c.AccessKeyId != v.AccessKeyID || c.SecretAccessKey != v.SecretAccessKey ||
		c.Token != v.SessionToken || c.ProviderName != v.Source {
		t.Error("data mismatch")
	}

	if !c.Expiration.IsZero() {
		t.Error("got non-zero expiration")
	}
}

func TestCredentials_FromStsCredentials(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		in := &types.Credentials{
			AccessKeyId:     aws.String("mockAK"),
			Expiration:      aws.Time(time.Unix(12345, 67890)),
			SecretAccessKey: aws.String("mockSK"),
			SessionToken:    aws.String("mockToken"),
		}

		c := FromStsCredentials(in)

		if c == nil {
			t.Error("nil output")
			return
		}

		if c.AccessKeyId != *in.AccessKeyId || c.SecretAccessKey != *in.SecretAccessKey || c.Token != *in.SessionToken {
			t.Error("data mismatch")
		}

		if c.Expiration.UnixNano() != 12345000067890 {
			t.Error("invalid expiration")
		}
	})

	t.Run("nil input", func(t *testing.T) {
		v := FromStsCredentials(nil)

		if v == nil {
			t.Error("nil output")
			return
		}

		if v.Value().HasKeys() {
			t.Error("found credentials with nil input")
		}

		if !v.Expiration.IsZero() {
			t.Error("found non-zero expiration")
		}
	})

	t.Run("zero value", func(t *testing.T) {
		v := FromStsCredentials(new(types.Credentials))

		if v == nil {
			t.Error("nil output")
			return
		}

		if v.Value().HasKeys() {
			t.Error("found credentials with nil input")
		}

		if !v.Expiration.IsZero() {
			t.Error("found non-zero expiration")
		}
	})
}

func matches(src []byte, elem ...string) bool {
	for _, e := range elem {
		if !bytes.Contains(src, []byte(e)) {
			return false
		}
	}
	return true
}
