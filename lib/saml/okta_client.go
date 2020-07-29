package saml

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type oktaSamlClient struct {
	*BaseAwsClient
}

// NewOktaSamlClient creates an Okta aware SAML client using authUrl as the authentication endpoint.
// The authUrl parameter will be in the form of https://your-okta-domain/home/amazon_aws/app-id/other-id
// This can be found in the 'App Embed Link' section of your AWS Okta App 'General' settings tab
func NewOktaSamlClient(authUrl string) (*oktaSamlClient, error) {
	bsc, err := newBaseAwsClient(authUrl)
	if err != nil {
		return nil, err
	}
	bsc.MfaType = MfaTypeAuto

	// the Okta authentication path uses redirects to get you from authUrl to a SAMLResponse,
	// so we need to allow them for this client
	bsc.httpClient.CheckRedirect = nil

	c := oktaSamlClient{BaseAwsClient: bsc}
	return &c, nil
}

func (c oktaSamlClient) Authenticate() error {
	if err := c.gatherCredentials(); err != nil {
		return nil
	}

	return c.auth()
}

func (c oktaSamlClient) AwsSaml() (string, error) {
	if err := c.samlRequest(c.authUrl); err != nil {
		return "", err
	}

	return c.rawSamlResponse, nil
}

func (c oktaSamlClient) auth() error {
	creds := map[string]string{
		"username": c.Username,
		"password": c.Password,
	}

	j, err := json.Marshal(&creds)
	if err != nil {
		return err
	}

	authUrl := fmt.Sprintf("%s://%s/api/v1/authn", c.authUrl.Scheme, c.authUrl.Host)
	res, err := http.Post(authUrl, "application/json", bytes.NewReader(j))
	if err != nil {
		return err
	}

	r, err := handleApiResponse(res)
	if err != nil {
		return err
	}

	switch r.Status {
	case "SUCCESS":
		// fall through
	case "MFA_REQUIRED":
		r, err = c.doMFA(r.StateToken, r.Details.MfaFactors)
		if err != nil {
			return new(errMfaFailure)
		}
	default:
		return fmt.Errorf("BAD STATUS: %s", r.Status)
	}

	u := *c.authUrl
	qs := url.Values{}
	qs.Add("sessionToken", r.SessionToken)
	u.RawQuery = qs.Encode()

	return c.samlRequest(&u)
}

func (c oktaSamlClient) doMFA(token string, factors []*mfaFactor) (*apiResponse, error) {
	if len(factors) == 1 {
		// single factor registered, just handle it
		return c.handleMfa(token, factors[0])
	}

	index := make(map[string]int)
	for i, f := range factors {
		if f.Type == "push" || strings.HasPrefix(f.Type, "token") {
			index[f.Type] = i
		}
	}

	switch len(index) {
	case 0:
		// fall through
	case 1:
		// sucks that we need to range(), but at least it's only one time
		for _, v := range index {
			return c.handleMfa(token, factors[v])
		}
	default:
		for _, e := range []string{"push", "token:software:totp", "token:hotp", "token"} {
			if v, ok := index[e]; ok {
				return c.handleMfa(token, factors[v])
			}
		}
	}

	return nil, new(errMfaNotConfigured)
}

func (c oktaSamlClient) handleMfa(token string, f *mfaFactor) (*apiResponse, error) {
	var verifyUrl string
	if v, ok := f.Links["verify"].(map[string]interface{}); ok {
		verifyUrl, _ = v["href"].(string)
	}

	switch f.Type {
	case "push":
		b := mfaResponse{Token: token}
		body, _ := json.Marshal(&b)
		res, err := c.httpClient.Post(verifyUrl, "application/json", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}

		r, err := handleApiResponse(res)
		if err != nil {
			return nil, err
		}

		return c.handlePushMfa(r)
	case "token", "token:hotp", "token:software:totp":
		return c.handleTokenMfa(token, verifyUrl)
	default:
		// fall through
	}

	return nil, fmt.Errorf("unsupported MFA Type: %s", f.Type)
}

func (c oktaSamlClient) handlePushMfa(res *apiResponse) (*apiResponse, error) {
	var err error

	fmt.Print("Waiting for Push MFA ")

	for strings.EqualFold(res.Status, "MFA_CHALLENGE") && strings.EqualFold(res.FactorResult, "WAITING") {
		var nextUrl string
		if v, ok := res.Links["next"].(map[string]interface{}); ok {
			nextUrl, _ = v["href"].(string)
		}

		b := mfaResponse{Token: res.StateToken}
		body, _ := json.Marshal(&b)

		time.Sleep(1250 * time.Millisecond)
		fmt.Print(".")

		r, err := c.httpClient.Post(nextUrl, "application/json", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}

		res, err = handleApiResponse(r)
		if err != nil {
			return nil, err
		}
	}
	return res, err
}

func (c oktaSamlClient) handleTokenMfa(token string, verifyUrl string) (*apiResponse, error) {
	if len(c.MfaToken) < 1 {
		if c.MfaTokenProvider != nil {
			t, err := c.MfaTokenProvider()
			if err != nil {
				return nil, err
			}
			c.MfaToken = t
		} else {
			return nil, new(errMfaNotConfigured)
		}
	}

	mfa := mfaResponse{Token: token, Code: c.MfaToken}
	data, _ := json.Marshal(mfa)
	res, err := http.Post(verifyUrl, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	// this is a re-tryable error (re-prompt for mfa code)
	if res.StatusCode != http.StatusOK {
		c.MfaToken = ""
		fmt.Println("invalid mfa code ... try again")
		return c.handleTokenMfa(token, verifyUrl)
	}

	r := new(apiResponse)
	if err := json.Unmarshal(body, r); err != nil {
		return nil, err
	}

	return r, nil
}

func handleApiResponse(res *http.Response) (*apiResponse, error) {
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		r := new(apiError)
		json.Unmarshal(body, r)
		return nil, fmt.Errorf("HTTP %d - %s (%s)", res.StatusCode, r.Message, r.Code)
	}

	r := new(apiResponse)
	if err := json.Unmarshal(body, r); err != nil {
		return nil, err
	}

	return r, nil
}

type apiError struct {
	Code    string `json:"errorCode"`
	Message string `json:"errorSummary"`
	Id      string `json:"errorId"`
}

type apiResponse struct {
	Status       string                 `json:"status"`
	StateToken   string                 `json:"stateToken"`
	SessionToken string                 `json:"sessionToken"`
	FactorResult string                 `json:"factorResult"`
	Details      responseDetail         `json:"_embedded"`
	Links        map[string]interface{} `json:"_links"`
}

type responseDetail struct {
	User       userDetails  `json:"user"`
	MfaFactors []*mfaFactor `json:"factors"`
}

type userDetails struct {
	Id      string            `json:"id"`
	Profile map[string]string `json:"profile"`
}

type mfaFactor struct {
	Id    string                 `json:"id"`
	Type  string                 `json:"factorType"`
	Links map[string]interface{} `json:"_links"`
}

type mfaResponse struct {
	Token string `json:"stateToken"`
	Code  string `json:"passCode,omitempty"`
}
