package credentials

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type OidcIdentityToken string

func (t *OidcIdentityToken) IsExpired() bool {
	return !t.ExpiresAt().After(time.Now())
}

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
