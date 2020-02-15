package saml

import (
	"fmt"
	"net/http"
	"strings"
)

// GetClient is a factory method for detecting the SAML client to use based on properties of an HTTP request
// the the provider's metadata endpoint
func GetClient(authUrl string, options ...func(s *BaseAwsClient)) (AwsClient, error) {
	var c AwsClient

	r, err := http.Head(authUrl)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	switch divineClient(r) {
	case "forgerock":
		c, err = NewForgerockSamlClient(authUrl)
	case "keycloak":
		c, err = NewKeycloakSamlClient(authUrl)
	case "onelogin":
		c, err = NewOneLoginSamlClient(authUrl)
	case "mock":
		c, err = NewMockSamlClient(authUrl)
	default:
		return nil, fmt.Errorf("unable to determine SAML client from url")
	}

	if err != nil {
		return nil, err
	}

	for _, f := range options {
		f(c.Client())
	}

	return c, nil
}

func divineClient(r *http.Response) string {
	if strings.Contains(r.Request.URL.Host, ".onelogin.com") {
		return "onelogin"
	}

	h := r.Header.Get("Access-Control-Allow-Headers")

	if strings.Contains(h, "X-OpenAM-") || strings.Contains(h, "MFA-FR-Token") {
		return "forgerock"
	}

	if strings.Contains(h, "X-MockTest-") {
		return "mock"
	}

	for _, c := range r.Cookies() {
		if c.Name == "KC_RESTART" {
			return "keycloak"
		}
	}

	return "unknown"
}
