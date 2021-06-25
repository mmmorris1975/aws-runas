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

package external

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/mmmorris1975/aws-runas/credentials"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewBaseClient(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c, err := newBaseClient("https://localhost/oauth2")
		if err != nil {
			t.Error(err)
			return
		}

		if c == nil {
			t.Error("nil client")
		}

		t.Logf("%+v", c)
	})

	t.Run("empty url", func(t *testing.T) {
		if _, err := newBaseClient(""); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("unparsable url", func(t *testing.T) {
		if _, err := newBaseClient("ht^p://localhost/"); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("invalid url", func(t *testing.T) {
		if _, err := newBaseClient("ftp://localhost/"); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestBaseClient_SetCookieJar(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		c, err := newBaseClient("http://localhost/")
		if err != nil {
			t.Error(err)
			return
		}
		c.SetCookieJar(nil)

		if c.httpClient.Jar != nil {
			t.Error("did not update cookie jar setting")
		}
	})

	t.Run("nil client", func(t *testing.T) {
		c, err := newBaseClient("http://localhost/")
		if err != nil {
			t.Error(err)
			return
		}
		c.httpClient = nil
		c.SetCookieJar(nil)

		if c.httpClient.Jar != nil {
			t.Error("did not update cookie jar setting")
		}
	})
}

func TestBaseClient_Roles(t *testing.T) {
	t.Run("oidc client", func(t *testing.T) {
		c, err := newBaseClient("https://localhost/")
		if err != nil {
			t.Error(err)
			return
		}
		c.ClientId = "client"
		c.RedirectUri = "redir"

		if _, err := c.roles(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("empty saml", func(t *testing.T) {
		c, err := newBaseClient("https://localhost/")
		if err != nil {
			t.Error(err)
			return
		}
		c.saml = new(credentials.SamlAssertion)

		if _, err := c.roles(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("nil saml", func(t *testing.T) {
		c, err := newBaseClient("https://localhost/")
		if err != nil {
			t.Error(err)
			return
		}

		if _, err := c.roles(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("good", func(t *testing.T) {
		//nolint:lll
		data := `<someTag>arn:aws:iam::01234567890:role/mockRole1,arn:aws:iam::01234567890:saml-provider/mockPrincipal1</someTag>`
		b64 := base64.StdEncoding.EncodeToString([]byte(data))
		a := credentials.SamlAssertion(b64)

		c, err := newBaseClient("https://localhost/")
		if err != nil {
			t.Error(err)
			return
		}
		c.saml = &a

		roles, err := c.roles()
		if err != nil {
			t.Error(err)
			return
		}

		if roles == nil || len(*roles) < 1 {
			t.Error("data mismatch")
			return
		}

		if !strings.Contains((*roles)[0], "mockRole") {
			t.Error("invalid role data")
		}
	})
}

func Test_identity(t *testing.T) {
	t.Run("invalid saml", func(t *testing.T) {
		saml := credentials.SamlAssertion("this is not saml")
		c := &baseClient{
			saml: &saml,
		}
		c.Username = "mockUser"

		id := c.identity("mock")
		if id.Provider != "mock" || id.Username != "mockUser" {
			t.Error("data mismatch")
		}
	})

	t.Run("valid saml", func(t *testing.T) {
		rawSaml := `<RoleSessionName>mockSamlUser</RoleSessionName>`
		saml := credentials.SamlAssertion(base64.StdEncoding.EncodeToString([]byte(rawSaml)))

		c := &baseClient{
			saml: &saml,
		}
		c.Username = "mockUser"

		id := c.identity("mock")
		if id.Provider != "mock" || id.Username != "mockSamlUser" {
			t.Error("data mismatch")
		}
	})
}

func Test_samlRequest(t *testing.T) {
	t.Run("invalid saml", func(t *testing.T) {
		saml := credentials.SamlAssertion("this is not saml")
		c := &baseClient{
			saml: &saml,
		}

		if err := c.samlRequest(context.Background(), new(url.URL)); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("valid saml", func(t *testing.T) {
		rawSaml := fmt.Sprintf(`<saml2:Assertion IssueInstant="%s">`, time.Now().Add(6*time.Hour).Format(time.RFC3339))
		saml := credentials.SamlAssertion(base64.StdEncoding.EncodeToString([]byte(rawSaml)))

		c := &baseClient{
			saml: &saml,
		}

		if err := c.samlRequest(context.Background(), new(url.URL)); err != nil {
			t.Error(err)
		}
	})
}
