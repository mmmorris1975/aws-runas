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
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// OidcIdentityToken provides a type for inspecting and managing an OIDC identity token used with
// the AssumeRoleWithWebIdentity AWS API call.
type OidcIdentityToken string

// IsExpired returns true if the identity token is expired, and needs to be refreshed from the provider.
func (t *OidcIdentityToken) IsExpired() bool {
	return !t.ExpiresAt().After(time.Now())
}

// ExpiresAt retrieves the 'exp' field from the identity token payload and returns it as a time.Time value.
func (t *OidcIdentityToken) ExpiresAt() time.Time {
	payload, err := t.decodePayload()
	if err != nil {
		return time.Time{}
	}

	switch v := payload["exp"].(type) {
	case float64:
		return time.Unix(int64(v), 0).Add(-1 * time.Minute)
	default:
		return time.Time{}
	}
}

func (t *OidcIdentityToken) String() string {
	if t == nil || len(*t) < 1 {
		return ""
	}
	return string(*t)
}

func (t *OidcIdentityToken) sections() ([]string, error) {
	// 3 parts ... header, payload, signature
	parts := strings.Split(string(*t), `.`)

	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}
	return parts, nil
}

func (t *OidcIdentityToken) decodePayload() (map[string]interface{}, error) {
	parts, err := t.sections()
	if err != nil {
		return nil, err
	}

	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	v := make(map[string]interface{})
	if err = json.Unmarshal(data, &v); err != nil {
		return nil, err
	}

	return v, nil
}
