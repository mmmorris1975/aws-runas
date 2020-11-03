package external

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

type pkceCode struct {
	challenge string
	verifier  string
}

func newPkceCode() (*pkceCode, error) {
	pkce := new(pkceCode)

	buf := make([]byte, 32) // required min length

	// Read() will always fill buf, unless error
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	pkce.verifier = base64.RawURLEncoding.EncodeToString(buf)

	h := sha256.New()
	h.Write([]byte(pkce.verifier))
	pkce.challenge = base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return pkce, nil
}

// Challenge returns the PKCE challenge value which is used in the 1st step of the OAuth/OIDC authentication flow
func (p *pkceCode) Challenge() string {
	return p.challenge
}

// Verifier returns the PKCE verifier value which is used in the final step of the OAuth/OIDC authentication flow
func (p *pkceCode) Verifier() string {
	return p.verifier
}
