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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
	"html"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const oktaIdentityProvider = "OktaIdentityProvider"

type oktaClient struct {
	*baseClient
	sessionToken string
}

// NewOktaClient returns a new AuthenticationClient capable of handling SAML and WebIdentity operations
// using the Okta identity platform.
func NewOktaClient(url string) (*oktaClient, error) {
	bc, err := newBaseClient(url)
	if err != nil {
		return nil, err
	}

	oc := new(oktaClient)
	oc.baseClient = bc

	return oc, nil
}

// Authenticate performs authentication against OneLogin.  This delegates to AuthenticateWithContext using
// context.Background().
func (c *oktaClient) Authenticate() error {
	return c.AuthenticateWithContext(context.Background())
}

// AuthenticateWithContext performs authentication against Okta using the specified Context, which is passed
// along to the underlying HTTP requests.  If necessary, it will prompt for the authentication credentials.
func (c *oktaClient) AuthenticateWithContext(ctx context.Context) error {
	if err := c.gatherCredentials(); err != nil {
		return err
	}

	res, err := c.auth(ctx)
	if err != nil {
		return err
	}

	c.sessionToken = res.SessionToken
	return nil
}

// Identity returns the identity information for the user.
func (c *oktaClient) Identity() (*identity.Identity, error) {
	return c.identity(oktaIdentityProvider), nil
}

// Roles retrieves the available roles for the user.  Attempting to call this method
// against an Oauth/OIDC client will return an error.
func (c *oktaClient) Roles(...string) (*identity.Roles, error) {
	if c.saml == nil || len(*c.saml) < 1 {
		var err error
		c.saml, err = c.SamlAssertion()
		if err != nil {
			return nil, err
		}
	}

	return c.roles()
}

// IdentityToken calls IdentityTokenWithContext with a background context.
func (c *oktaClient) IdentityToken() (*credentials.OidcIdentityToken, error) {
	return c.IdentityTokenWithContext(context.Background())
}

// IdentityTokenWithContext retrieves the OIDC Identity Token from Okta. Authentication will automatically be attempted,
// if required.
func (c *oktaClient) IdentityTokenWithContext(ctx context.Context) (*credentials.OidcIdentityToken, error) {
	pkce, err := newPkceCode()
	if err != nil {
		return nil, err
	}
	authzQS := c.pkceAuthzRequest(pkce.Challenge())

	if len(c.sessionToken) > 0 {
		authzQS.Set("sessionToken", c.sessionToken) // okta specific requirement
	}

	var vals url.Values
	vals, err = c.oauthAuthorize(fmt.Sprintf("%s/v1/authorize", c.authUrl.String()), authzQS, false)
	if err != nil {
		return nil, err
	}

	if len(vals.Get("fromURI")) > 0 {
		// This is an indication that an unauthenticated (or expired session) request was attempted
		if err = c.AuthenticateWithContext(ctx); err != nil {
			return nil, err
		}
		return c.IdentityToken()
	}

	if vals.Get("state") != authzQS.Get("state") {
		return nil, errOauthStateMismatch
	}

	token, err := c.oauthToken(fmt.Sprintf("%s/v1/token", c.authUrl.String()), vals.Get("code"), pkce.Verifier())
	if err != nil {
		return nil, err
	}

	return token.IdToken, nil
}

// SamlAssertion calls SamlAssertionWithContext using a background context.
func (c *oktaClient) SamlAssertion() (*credentials.SamlAssertion, error) {
	return c.SamlAssertionWithContext(context.Background())
}

// SamlAssertionWithContext retrieves the SAML Assertion from Okta.
// Authentication will automatically be attempted, if required.
func (c *oktaClient) SamlAssertionWithContext(ctx context.Context) (*credentials.SamlAssertion, error) {
	u := *c.authUrl
	qs := url.Values{}

	if len(c.sessionToken) > 0 {
		qs.Add("sessionToken", c.sessionToken) // okta specific requirement
	}
	u.RawQuery = qs.Encode()

	if err := c.samlRequest(ctx, &u); err != nil {
		return nil, err
	}

	if c.saml == nil || len(*c.saml) < 1 {
		if err := c.AuthenticateWithContext(ctx); err != nil {
			return nil, err
		}
		return c.SamlAssertionWithContext(ctx)
	}

	return c.saml, nil
}

func (c *oktaClient) auth(ctx context.Context) (*oktaAuthnResponse, error) {
	res, err := c.sendAuthnRequest(ctx)
	if err != nil {
		return nil, err
	}

	switch strings.ToUpper(res.Status) {
	case "SUCCESS":
		return res, nil
	case "MFA_REQUIRED":
		return c.doMfa(ctx, res.StateToken, res.EmbeddedData.MfaFactors)
	default:
		return nil, fmt.Errorf("authentication status %s", res.Status)
	}
}

func (c *oktaClient) sendAuthnRequest(ctx context.Context) (*oktaAuthnResponse, error) {
	creds, err := json.Marshal(map[string]string{
		"username": c.Username,
		"password": c.Password,
	})
	if err != nil {
		return nil, err
	}

	authUrl := fmt.Sprintf("%s://%s/api/v1/authn", c.authUrl.Scheme, c.authUrl.Host)
	res, err := c.sendApiRequst(ctx, authUrl, bytes.NewReader(creds))
	if err != nil {
		return nil, err
	}

	return c.handleAuthResponse(res)
}

//nolint:gocognit // won't simplify
func (c *oktaClient) doMfa(ctx context.Context, stateToken string, factors []*oktaMfaFactor) (*oktaAuthnResponse, error) {
	// don't try to short-circuit with a len(factors) == 1 case, since it could be a factor we dont' support
	// we need to loop through the provided factors, and choose only the supported types
	index := make(map[string]int)
	for i, f := range factors {
		// do we need to be smart about this, or just assume that DUO is the only factor used?
		if strings.EqualFold(f.Provider, "duo") {
			return c.handleDuoMfa(ctx, stateToken, f)
		}

		if f.FactorType == "push" || strings.HasPrefix(f.FactorType, "token") {
			index[f.FactorType] = i
		}
	}

	switch len(index) {
	case 0:
		// fall through
	case 1:
		for _, v := range index {
			return c.handleMfa(ctx, stateToken, factors[v])
		}
	default:
		switch strings.ToLower(c.MfaType) {
		case MfaTypePush:
			if v, ok := index[c.MfaType]; ok {
				return c.handleMfa(ctx, stateToken, factors[v])
			}
		case MfaTypeCode:
			for _, e := range []string{"token:software:totp", "token:hotp", "token"} {
				if v, ok := index[e]; ok {
					return c.handleMfa(ctx, stateToken, factors[v])
				}
			}
		default:
			for _, e := range []string{"push", "token:software:totp", "token:hotp", "token"} {
				if v, ok := index[e]; ok {
					return c.handleMfa(ctx, stateToken, factors[v])
				}
			}
		}
	}

	return nil, errMfaNotConfigured
}

func (c *oktaClient) handleDuoMfa(ctx context.Context, stateToken string, factor *oktaMfaFactor) (*oktaAuthnResponse, error) {
	verifyUrl := factor.Links["verify"].Href
	body, _ := json.Marshal(oktaMfaResponse{Token: stateToken})
	res, err := c.sendApiRequst(ctx, verifyUrl, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	var r *oktaAuthnResponse
	r, err = c.handleAuthResponse(res)
	if err != nil {
		return nil, err
	}

	if err = c.submitDuoMfa(ctx, r); err != nil {
		return nil, err
	}

	// Duo MFA done, complete Okta MFA login workflow
	var nextUrl string
	if v, ok := r.Links["next"].(map[string]interface{}); ok {
		nextUrl, _ = v["href"].(string)
	}

	body, _ = json.Marshal(oktaMfaResponse{Token: r.StateToken})
	res, err = c.sendApiRequst(ctx, nextUrl, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	return c.handleAuthResponse(res)
}

func (c *oktaClient) submitDuoMfa(ctx context.Context, r *oktaAuthnResponse) error {
	attrsJson, err := json.Marshal(r.EmbeddedData.MfaFactor.EmbeddedData["verification"])
	if err != nil {
		return err
	}

	duoAttrs := new(oktaDuoAttrs)
	if err = json.Unmarshal(attrsJson, duoAttrs); err != nil {
		return err
	}

	var duoSid string
	duoSid, err = c.fetchDuoSid(ctx, duoAttrs)
	if err != nil {
		return err
	}

	// this is what triggers the push MFA prompting
	var txn *oktaDuoTxn
	txn, err = c.fetchDuoTxn(ctx, duoAttrs.Host, duoSid)
	if err != nil {
		return err
	} else if txn.Stat != "OK" {
		return errors.New("error authorizing mfa device")
	}

	var cookie string
	cookie, err = c.fetchDuoCookie(ctx, duoAttrs.Host, duoSid, txn.Response.Txid)
	if err != nil {
		return err
	}

	form := url.Values{}
	form.Add("id", r.EmbeddedData.MfaFactor.Id)
	form.Add("stateToken", r.StateToken)

	sigParts := strings.Split(duoAttrs.Signature, `:`)
	form.Add("sig_response", fmt.Sprintf("%s:%s", cookie, sigParts[1]))

	var req *httpRequest
	req, err = newHttpRequest(ctx, "POST", duoAttrs.Links.Complete.Href)
	if err != nil {
		return err
	}
	req.withContentType("application/x-www-form-urlencoded").withValues(form)

	// successful response is a http 200 with no response body
	var res *http.Response
	res, err = checkResponseError(c.httpClient.Do(req.Request))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

func (c *oktaClient) fetchDuoSid(ctx context.Context, attrs *oktaDuoAttrs) (string, error) {
	duoForm := url.Values{}
	duoForm.Add("parent", fmt.Sprintf("https://%s/signin/verify/duo/web", c.authUrl.Host))
	duoForm.Add("java_version", "")
	duoForm.Add("java_version", "")
	duoForm.Add("flash_version", "")
	duoForm.Add("screen_resolution_width", "3008")
	duoForm.Add("screen_resolution_height", "1692")
	duoForm.Add("color_depth", "24")

	req, err := newHttpRequest(ctx, "POST", fmt.Sprintf("https://%s/frame/web/v1/auth", attrs.Host))
	if err != nil {
		return "", err
	}
	req.withContentType("application/x-www-form-urlencoded").withValues(duoForm)

	duoSigParts := strings.Split(attrs.Signature, `:`)
	q := req.URL.Query()
	q.Add("tx", duoSigParts[0])
	req.URL.RawQuery = q.Encode()

	var res *http.Response
	res, err = checkResponseError(c.httpClient.Do(req.Request))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	// try to extract sid
	var doc *goquery.Document
	doc, err = goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return "", err
	}

	duoSID, ok := doc.Find("input[name=\"sid\"]").Attr("value")
	if !ok {
		return "", nil
	}

	return html.UnescapeString(duoSID), nil
}

//nolint:gocognit
func (c *oktaClient) fetchDuoTxn(ctx context.Context, host, sid string) (*oktaDuoTxn, error) {
	duoForm := url.Values{}
	duoForm.Add("sid", sid)
	duoForm.Add("device", "phone1")
	duoForm.Add("factor", "Duo Push")
	duoForm.Add("out_of_date", "false")

	if c.MfaType == MfaTypeCode {
		if len(c.MfaTokenCode) < 1 {
			if c.MfaTokenProvider != nil {
				t, err := c.MfaTokenProvider()
				if err != nil {
					return nil, err
				}
				c.MfaTokenCode = t
			} else {
				return nil, errMfaNotConfigured
			}
		}

		duoForm.Set("factor", "Passcode")
		duoForm.Add("passcode", c.MfaTokenCode)
	} else {
		fmt.Print("Waiting for Push MFA ...")
	}

	req, err := newHttpRequest(ctx, "POST", fmt.Sprintf("https://%s/frame/prompt", host))
	if err != nil {
		return nil, err
	}
	req.withContentType("application/x-www-form-urlencoded").withValues(duoForm)

	var res *http.Response
	res, err = checkResponseError(c.httpClient.Do(req.Request))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var body []byte
	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	txn := new(oktaDuoTxn)
	if err = json.Unmarshal(body, txn); err != nil {
		return nil, err
	}

	return txn, nil
}

func (c *oktaClient) fetchDuoCookie(ctx context.Context, host, sid, txid string) (string, error) {
	duoForm := url.Values{}
	duoForm.Add("sid", sid)
	duoForm.Add("txid", txid)

	req, err := newHttpRequest(ctx, "POST", fmt.Sprintf("https://%s/frame/status", host))
	if err != nil {
		return "", err
	}
	req.withContentType("application/x-www-form-urlencoded").withValues(duoForm)

	var res *http.Response
	res, err = checkResponseError(c.httpClient.Do(req.Request))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	var body []byte
	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	result := new(oktaDuoResponse)
	if err = json.Unmarshal(body, result); err != nil {
		return "", err
	}

OUTER:
	for {
		switch result.Response.Result {
		case "SUCCESS":
			break OUTER
		case "FAILURE":
			return "", errors.New("failed to complete multi-factor authentication")
		default:
			time.Sleep(1 * time.Second)
			return c.fetchDuoCookie(ctx, host, sid, txid)
		}
	}

	if len(result.Response.Sid) > 0 {
		sid = result.Response.Sid
	}

	duoForm = url.Values{}
	duoForm.Add("sid", sid)

	req, err = newHttpRequest(ctx, "POST", fmt.Sprintf("https://%s%s", host, result.Response.ResultUrl))
	if err != nil {
		return "", err
	}
	req.withContentType("application/x-www-form-urlencoded").withValues(duoForm)

	res, err = checkResponseError(c.httpClient.Do(req.Request))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	result = new(oktaDuoResponse)
	if err = json.Unmarshal(body, result); err != nil {
		return "", err
	}

	if result.Stat != "OK" {
		return "", fmt.Errorf("mfa result: %s, message: %s", result.Stat, result.Message)
	}

	return result.Response.Cookie, nil
}

func (c *oktaClient) handleMfa(ctx context.Context, stateToken string, factor *oktaMfaFactor) (*oktaAuthnResponse, error) {
	verifyUrl := factor.Links["verify"].Href

	switch factor.FactorType {
	case "push":
		// send push notification
		body, _ := json.Marshal(oktaMfaResponse{Token: stateToken})

		res, err := c.sendApiRequst(ctx, verifyUrl, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}

		r, err := c.handleAuthResponse(res)
		if err != nil {
			return nil, err
		}

		// handle push response
		return c.handlePushMfa(ctx, r)
	case "token", "token:hotp", "token:software:totp":
		return c.handleTokenMfa(ctx, stateToken, verifyUrl)
	default:
		return nil, fmt.Errorf("unsupported MFA Type: %s", factor.FactorType)
	}
}

func (c *oktaClient) handlePushMfa(ctx context.Context, res *oktaAuthnResponse) (*oktaAuthnResponse, error) {
	var err error

	fmt.Print("Waiting for Push MFA ")

	for strings.EqualFold(res.Status, "MFA_CHALLENGE") && strings.EqualFold(res.FactorResult, "WAITING") {
		var nextUrl string
		if v, ok := res.Links["next"].(map[string]interface{}); ok {
			nextUrl, _ = v["href"].(string)
		}

		body, _ := json.Marshal(oktaMfaResponse{Token: res.StateToken})

		time.Sleep(1250 * time.Millisecond)
		fmt.Print(".")

		var r *http.Response
		r, err = c.sendApiRequst(ctx, nextUrl, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}

		res, err = c.handleAuthResponse(r)
		if err != nil {
			return nil, err
		}
	}
	return res, err
}

func (c *oktaClient) handleTokenMfa(ctx context.Context, stateToken, url string) (*oktaAuthnResponse, error) {
	if len(c.MfaTokenCode) < 1 {
		if c.MfaTokenProvider != nil {
			t, err := c.MfaTokenProvider()
			if err != nil {
				return nil, err
			}
			c.MfaTokenCode = t
		} else {
			return nil, errMfaNotConfigured
		}
	}

	mfa := oktaMfaResponse{Token: stateToken, Code: c.MfaTokenCode}
	data, _ := json.Marshal(mfa)

	res, err := c.sendApiRequst(ctx, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	// this is a re-tryable error (re-prompt for mfa code)
	if res.StatusCode != http.StatusOK {
		_ = res.Body.Close()
		c.MfaTokenCode = ""
		fmt.Println("invalid mfa code ... try again")
		return c.handleTokenMfa(ctx, stateToken, url)
	}

	return c.handleAuthResponse(res)
}

func (c *oktaClient) sendApiRequst(ctx context.Context, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return c.httpClient.Do(req)
}

func (c *oktaClient) handleAuthResponse(res *http.Response) (*oktaAuthnResponse, error) {
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	// any non-200 status code is bad (invalid creds, locked out), reason will be provided in response body
	if res.StatusCode != http.StatusOK {
		r := new(oktaApiError)
		_ = json.Unmarshal(body, r)
		return nil, r
	}

	or := new(oktaAuthnResponse)
	if err := json.Unmarshal(body, or); err != nil {
		return nil, err
	}
	return or, nil
}

type oktaAuthnResponse struct {
	Status       string                 `json:"status"`
	SessionToken string                 `json:"sessionToken,omitempty"`
	StateToken   string                 `json:"stateToken,omitempty"`
	FactorResult string                 `json:"factorResult"`
	Links        map[string]interface{} `json:"_links"`
	EmbeddedData struct {
		MfaFactors []*oktaMfaFactor `json:"factors"`
		MfaFactor  *oktaMfaFactor   `json:"factor"`
	} `json:"_embedded,omitempty"`
}

type oktaMfaFactor struct {
	Id         string `json:"id"`
	FactorType string `json:"factorType"`
	Provider   string `json:"provider"`
	Links      map[string]struct {
		Href string `json:"href"`
	} `json:"_links"`
	EmbeddedData map[string]map[string]interface{} `json:"_embedded,omitempty"`
}

type oktaMfaResponse struct {
	Token string `json:"stateToken"`
	Code  string `json:"passCode,omitempty"`
}

type oktaApiError struct {
	Code    string `json:"errorCode"`
	Message string `json:"errorSummary"`
	Id      string `json:"errorId"`
}

type oktaDuoAttrs struct {
	Links struct {
		Complete struct {
			Hints struct {
				Allow []string `json:"allow"`
			} `json:"hints"`
			Href string `json:"href"`
		} `json:"complete"`
		Script struct {
			Href string `json:"href"`
			Type string `json:"type"`
		} `json:"script"`
	} `json:"_links"`
	FactorResult string `json:"factorResult"`
	Host         string `json:"host"`
	Signature    string `json:"signature"`
}

type oktaDuoTxn struct {
	Stat     string `json:"stat"`
	Response struct {
		Txid string `json:"txid"`
	} `json:"response"`
}

type oktaDuoResponse struct {
	Stat     string `json:"stat"`
	Message  string `json:"message"`
	Response struct {
		Cookie     string `json:"cookie"`
		Result     string `json:"result"`
		ResultUrl  string `json:"result_url"`
		Sid        string `json:"sid"`
		Status     string `json:"status"`
		StatusCode string `json:"status_code"`
	} `json:"response"`
}

func (e *oktaApiError) Error() string {
	return e.Message
}
