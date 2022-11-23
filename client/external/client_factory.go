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
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mmmorris1975/aws-runas/shared"
)

const (
	forgerockProvider = "forgerock"
	keycloakProvider  = "keycloak"
	oneloginProvider  = "onelogin"
	oktaProvider      = "okta"
	mockProvider      = "mock"
	unknownProvider   = "unknown"
	azureadProvider   = "azuread"
	browserProvider   = "browser"
)

var errUnknownProvider = errors.New("unable to determine client provider type")

// GetSamlClient returns a SamlClient based on the supplied provider and/or authUrl parameters.  The cfg parameter
// is applied as the client configuration, once resolved.
func GetSamlClient(provider, authUrl string, cfg AuthenticationClientConfig) (SamlClient, error) {
	c, err := lookupClient(provider, authUrl, OidcClientConfig{AuthenticationClientConfig: cfg})
	if err != nil {
		return nil, err
	}
	return c.(SamlClient), nil
}

// MustGetSamlClient calls GetSamlClient and panics if an error is returned.
func MustGetSamlClient(provider, authUrl string, cfg AuthenticationClientConfig) SamlClient {
	c, err := GetSamlClient(provider, authUrl, cfg)
	if err != nil {
		panic(err)
	}
	return c
}

// GetWebIdentityClient returns a WebIdentityClient based on the supplied provider and/or authUrl parameters.
// The cfg parameter is applied as the client configuration, once resolved.
func GetWebIdentityClient(provider, authUrl string, cfg OidcClientConfig) (WebIdentityClient, error) {
	c, err := lookupClient(provider, authUrl, cfg)
	if err != nil {
		return nil, err
	}
	return c.(WebIdentityClient), nil
}

// MustGetWebIdentityClient calls GetWebIdentityClient and panics if an error is returned.
func MustGetWebIdentityClient(provider, authUrl string, cfg OidcClientConfig) WebIdentityClient {
	c, err := GetWebIdentityClient(provider, authUrl, cfg)
	if err != nil {
		panic(err)
	}
	return c
}

// the switch statement will continue to grow as new providers are added, so keep the linter quiet
//
//nolint:gocyclo,funlen,gocognit
func lookupClient(provider, authUrl string, cfg OidcClientConfig) (interface{}, error) {
	if len(provider) < 1 {
		provider = divineClient(authUrl, http.MethodHead)
	}

	if cfg.Logger == nil {
		cfg.Logger = new(shared.DefaultLogger)
	}

	switch strings.ToLower(provider) {
	case forgerockProvider:
		c, err := NewForgerockClient(authUrl)
		if err != nil {
			return nil, err
		}
		c.OidcClientConfig = cfg
		c.Logger = cfg.Logger
		c.MfaType = cfg.MfaType
		return c, nil
	case keycloakProvider:
		c, err := NewKeycloakClient(authUrl)
		if err != nil {
			return nil, err
		}
		c.OidcClientConfig = cfg
		c.Logger = cfg.Logger
		c.MfaType = cfg.MfaType
		return c, nil
	case oneloginProvider:
		c, err := NewOneloginClient(authUrl)
		if err != nil {
			return nil, err
		}
		c.OidcClientConfig = cfg
		c.Logger = cfg.Logger
		c.MfaType = cfg.MfaType
		return c, nil
	case oktaProvider:
		c, err := NewOktaClient(authUrl)
		if err != nil {
			return nil, err
		}
		c.OidcClientConfig = cfg
		c.Logger = cfg.Logger
		c.MfaType = cfg.MfaType
		return c, nil
	case mockProvider:
		c, err := NewMockClient(authUrl)
		if err != nil {
			return nil, err
		}
		c.OidcClientConfig = cfg
		c.Logger = cfg.Logger
		c.MfaType = cfg.MfaType
		return c, nil
	case azureadProvider:
		c, err := NewAadClient(authUrl)
		if err != nil {
			return nil, err
		}
		c.OidcClientConfig = cfg
		c.Logger = cfg.Logger
		c.MfaType = cfg.MfaType
		return c, nil
	case browserProvider:
		c, err := NewBrowserClient(authUrl)
		if err != nil {
			return nil, err
		}
		c.OidcClientConfig = cfg
		c.Logger = cfg.Logger
		c.MfaType = cfg.MfaType
		return c, nil
	default:
		return nil, errUnknownProvider
	}
}

func divineClient(u, method string) string {
	// somewhat arbitrary timeout, but should hopefully work for most things
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	r, err := http.NewRequestWithContext(ctx, method, u, http.NoBody)
	if err != nil {
		return ""
	}

	// test if URL explicitly calls out a provider, and bypass any outbound requests
	switch h := strings.ToLower(r.URL.Host); {
	case strings.HasSuffix(h, ".okta.com"):
		return oktaProvider
	case strings.HasSuffix(h, ".onelogin.com"):
		return oneloginProvider
	case strings.HasSuffix(h, ".microsoft.com"):
		return azureadProvider
	case strings.HasPrefix(h, "localhost") || strings.HasPrefix(h, "127.0.0.1") || strings.HasPrefix(h, "[::1]"):
		if strings.HasPrefix(r.URL.Path, "/mock") {
			return mockProvider
		}
	}

	errCh := make(chan error, 1)
	resCh := make(chan *http.Response, 1)
	go func(req *http.Request) {
		// we don't care about the HTTP status, nearly all non-200 responses contain the info we need
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		defer res.Body.Close()
		resCh <- res
	}(r)
	defer func() {
		close(errCh)
		close(resCh)
	}()

	select {
	case res := <-resCh:
		return checkResult(res)
	case <-errCh:
		// fall through
	case <-ctx.Done():
		// timeout -- retry as GET request (possible WAF blocking HEAD requests?)
		if ctx.Err() == context.DeadlineExceeded && method != http.MethodGet {
			return divineClient(u, http.MethodGet)
		}
	}

	return unknownProvider
}

func checkResult(res *http.Response) string {
	// Test for provider-specific headers
	hdr := res.Header.Get("Access-Control-Allow-Headers")
	if strings.Contains(hdr, "X-OpenAM-") || strings.Contains(hdr, "MFA-FR-Token") {
		return forgerockProvider
	}

	if len(res.Header.Get("x-okta-request-id")) > 0 {
		return oktaProvider
	}

	if len(res.Header.Get("x-ms-request-id")) > 0 {
		return azureadProvider
	}

	// Test for provider-specific cookies
	for _, c := range res.Cookies() {
		// fixme will not be present with bare oidc path (requires valid query string for /auth endpoint)
		if strings.EqualFold(c.Name, "KC_RESTART") {
			return keycloakProvider
		}

		if strings.Contains(strings.ToLower(c.Name), "_onelogin.com") {
			return oneloginProvider
		}
	}

	return unknownProvider
}
