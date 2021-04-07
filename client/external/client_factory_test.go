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
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var mockExternalProvider = httptest.NewServer(http.HandlerFunc(mockExternalHandler))

func TestMustGetSamlClient(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling %s MustGetSamlClient", unknownProvider)
			}
		}()
		u := fmt.Sprintf("%s/%s", mockExternalProvider.URL, "this_should_fail")
		MustGetSamlClient("", u, AuthenticationClientConfig{})
	})

	t.Run("explicit provider", func(t *testing.T) {
		MustGetSamlClient(oktaProvider, "http://test.okta.com", AuthenticationClientConfig{})
	})
}

func TestMustGetSamlClient_Okta(t *testing.T) {
	t.Run("public url", func(t *testing.T) {
		MustGetSamlClient("", "http://test.okta.com", AuthenticationClientConfig{})
	})

	t.Run("custom url", func(t *testing.T) {
		u := fmt.Sprintf("%s/%s", mockExternalProvider.URL, oktaProvider)
		MustGetSamlClient("", u, AuthenticationClientConfig{})
	})

	t.Run("bad", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling %s MustGetSamlClient", oktaProvider)
			}
		}()
		// okta only fails with an invalid url
		MustGetSamlClient("", "telnet://test.okta.com", AuthenticationClientConfig{})
	})
}

// The Onelogin client requires access to a Onelogin endpoint to get an API access token
// use the mock endpoint in the onelogin_client_test file for testing.
func TestMustGetSamlClient_Onelogin(t *testing.T) {
	s := oneloginMock
	qs := url.Values{}
	qs.Add("token", base64.URLEncoding.EncodeToString([]byte("mockClientId:mockClientSecret")))

	t.Run("public url", func(t *testing.T) {
		t.Skip("can not test against Onelogin public URL without valid API credentials") // not testable
	})

	t.Run("custom url", func(t *testing.T) {
		u := fmt.Sprintf("%s/%s?%s", s.URL, oneloginProvider, qs.Encode())
		MustGetSamlClient("", u, AuthenticationClientConfig{})
	})

	t.Run("bad", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling %s MustGetSamlClient", oneloginProvider)
			}
		}()
		// onelogin url requires extra parameters in the query string
		MustGetSamlClient("", "https://test.onelogin.com", AuthenticationClientConfig{})
	})
}

func TestMustGetSamlClient_Forgerock(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		u := fmt.Sprintf("%s/%s/json/realms/test", mockExternalProvider.URL, forgerockProvider)
		MustGetSamlClient("", u, AuthenticationClientConfig{})
	})

	t.Run("bad", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling %s MustGetSamlClient", forgerockProvider)
			}
		}()
		u := fmt.Sprintf("%s/%s", mockExternalProvider.URL, forgerockProvider)
		MustGetSamlClient("", u, AuthenticationClientConfig{})
	})
}

func TestMustGetSamlClient_Keycloak(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		u := fmt.Sprintf("%s/%s/realms/test/protocol/saml/clients/1234", mockExternalProvider.URL, keycloakProvider)
		MustGetSamlClient("", u, AuthenticationClientConfig{})
	})

	t.Run("bad", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling %s MustGetSamlClient", keycloakProvider)
			}
		}()
		// keycloak only fails with an invalid url, so explicitly set provider name to bypass probing
		MustGetSamlClient(keycloakProvider, "gopher://test.keycloak.local/", AuthenticationClientConfig{})
	})
}

func TestMustGetSamlClient_AzureAD(t *testing.T) {
	t.Run("public url", func(t *testing.T) {
		MustGetSamlClient("", "http://test.microsoft.com/signin/myAppId?tenantId=myTenantId", AuthenticationClientConfig{})
	})

	t.Run("custom url", func(t *testing.T) {
		u := fmt.Sprintf("%s/%s/signin/myAppId?tenantId=myTenantId", mockExternalProvider.URL, azureadProvider)
		MustGetSamlClient("", u, AuthenticationClientConfig{})
	})

	t.Run("bad", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling %s MustGetSamlClient", oktaProvider)
			}
		}()

		MustGetSamlClient("", "telnet://test.microsoft.com", AuthenticationClientConfig{})
	})
}

func TestMustGetWebIdentityClient(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling %s MustGetWebIdentityClient", unknownProvider)
			}
		}()
		u := fmt.Sprintf("%s/%s", mockExternalProvider.URL, "this_should_fail")
		MustGetWebIdentityClient("", u, OidcClientConfig{})
	})

	t.Run("explicit provider", func(t *testing.T) {
		MustGetWebIdentityClient(oktaProvider, "http://test.okta.com", OidcClientConfig{})
	})
}

func TestMustGetWebIdentityClient_Okta(t *testing.T) {
	t.Run("public url", func(t *testing.T) {
		MustGetWebIdentityClient("", "http://test.okta.com", OidcClientConfig{})
	})

	t.Run("custom url", func(t *testing.T) {
		u := fmt.Sprintf("%s/%s", mockExternalProvider.URL, oktaProvider)
		MustGetWebIdentityClient("", u, OidcClientConfig{})
	})

	t.Run("bad", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling %s MustGetWebIdentityClient", oktaProvider)
			}
		}()
		// okta only fails with an invalid url
		MustGetWebIdentityClient("", "telnet://test.okta.com", OidcClientConfig{})
	})
}

// The Onelogin client requires access to a Onelogin endpoint to get an API access token
// use the mock endpoint in the onelogin_client_test file for testing.
func TestMustGetWebIdentityClient_Onelogin(t *testing.T) {
	s := oneloginMock

	t.Run("public url", func(t *testing.T) {
		t.Skip("can not test against Onelogin public URL without valid API credentials") // not testable
	})

	t.Run("custom url", func(t *testing.T) {
		qs := url.Values{}
		qs.Add("token", base64.URLEncoding.EncodeToString([]byte("mockClientId:mockClientSecret")))
		u := fmt.Sprintf("%s/%s?%s", s.URL, oneloginProvider, qs.Encode())
		MustGetWebIdentityClient("", u, OidcClientConfig{})
	})

	t.Run("bad", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling %s MustGetWebIdentityClient", oneloginProvider)
			}
		}()
		// onelogin url requires extra parameters in the query string
		MustGetWebIdentityClient("", "https://test.onelogin.com", OidcClientConfig{})
	})
}

func TestMustGetWebIdentityClient_Forgerock(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		u := fmt.Sprintf("%s/%s/oauth2/realms/test", mockExternalProvider.URL, forgerockProvider)
		MustGetWebIdentityClient("", u, OidcClientConfig{})
	})

	t.Run("bad", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling %s MustGetWebIdentityClient", forgerockProvider)
			}
		}()
		u := fmt.Sprintf("%s/%s", mockExternalProvider.URL, forgerockProvider)
		MustGetWebIdentityClient("", u, OidcClientConfig{})
	})
}

func TestMustGetWebIdentityClient_Keycloak(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		u := fmt.Sprintf("%s/%s/realms/test", mockExternalProvider.URL, keycloakProvider)
		MustGetWebIdentityClient("", u, OidcClientConfig{})
	})

	t.Run("bad", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling %s MustGetWebIdentityClient", keycloakProvider)
			}
		}()
		// keycloak only fails with an invalid url, so explicitly set provider name to bypass probing
		MustGetWebIdentityClient(keycloakProvider, "gopher://test.keycloak.local/", OidcClientConfig{})
	})
}

func Test_lookupClient_Mock(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		c, err := lookupClient("mock", "http://localhost", OidcClientConfig{})
		if err != nil {
			t.Error(err)
			return
		}

		if _, ok := c.(*mockClient); !ok {
			t.Error("not a mock client")
		}
	})

	t.Run("bad url", func(t *testing.T) {
		if _, err := lookupClient("mock", "gopher://localhost", OidcClientConfig{}); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestMustGetWebIdentityClient_AzureAD(t *testing.T) {
	t.Run("public url", func(t *testing.T) {
		MustGetWebIdentityClient("", "http://test.microsoft.com/signin/myAppId?tenantId=myTenantId", OidcClientConfig{})
	})

	t.Run("custom url", func(t *testing.T) {
		u := fmt.Sprintf("%s/%s/signin/myAppId?tenantId=myTenantId", mockExternalProvider.URL, azureadProvider)
		MustGetWebIdentityClient("", u, OidcClientConfig{})
	})

	t.Run("bad", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling %s MustGetSamlClient", oktaProvider)
			}
		}()

		MustGetWebIdentityClient("", "telnet://test.microsoft.com", OidcClientConfig{})
	})
}

func mockExternalHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	switch strings.Split(r.URL.Path, `/`)[1] {
	case oktaProvider:
		w.Header().Set("x-okta-request-id", "abc123")
		_, _ = w.Write(nil)
	case oneloginProvider:
		http.SetCookie(w, &http.Cookie{
			Name:  "sub_session_onelogin.com",
			Value: "abc123",
		})
		_, _ = w.Write(nil)
	case forgerockProvider:
		w.Header().Set("Access-Control-Allow-Headers", "X-OpenAM-Username,X-OpenAM-Password")
		_, _ = w.Write(nil)
	case keycloakProvider:
		http.SetCookie(w, &http.Cookie{
			Name:  "KC_RESTART",
			Value: "abc123",
		})
		_, _ = w.Write(nil)
	case azureadProvider:
		w.Header().Set("x-ms-request-id", "abc123")
		_, _ = w.Write(nil)
	default:
		http.NotFound(w, r)
	}
}
