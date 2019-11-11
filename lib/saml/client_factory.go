package saml

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// GetClient is a factory method for detecting the SAML client to use based on properties of an HTTP request
// the the provider's metadata endpoint
func GetClient(mdUrl string, options ...func(s *SamlClient)) (AwsSamlClient, error) {
	var c AwsSamlClient

	r, err := http.Get(mdUrl)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP code: %d", r.StatusCode)
	}

	switch divineClient(r) {
	case "forgerock":
		c, err = NewForgerockSamlClient(mdUrl)
		if err != nil {
			return nil, err
		}
	case "keycloak":
		c, err = NewKeycloakSamlClient(mdUrl)
		if err != nil {
			return nil, err
		}
	case "mock":
		c, err = NewMockSamlClient(mdUrl)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unable to determine SAML client from metadata")
	}

	for _, f := range options {
		f(c.Client())
	}

	return c, nil
}

func divineClient(r *http.Response) string {
	h := r.Header.Get("Access-Control-Allow-Headers")

	if strings.Contains(h, "X-OpenAM-") || strings.Contains(h, "MFA-FR-Token") {
		return "forgerock"
	}

	if strings.Contains(h, "X-MockTest-") {
		return "mock"
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err.Error()
	}

	if strings.Contains(string(body), "urn:keycloak") {
		return "keycloak"
	}

	return "unknown"
}
