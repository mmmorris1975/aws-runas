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
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	aadIdentityProvider   = "AzureADIdentityProvider"
	aadBadUserPassErrCode = 50126
	aadInvalidMfaCode     = 500121

	mfaMethodNotify = "PhoneAppNotification"
	mfaMethodOTP    = "PhoneAppOTP"
	mfaMethodSMS    = "OneWaySMS"
)

var (
	bodyRe = regexp.MustCompile(`\$Config=({.+?});`)
	samlRe = regexp.MustCompile(`window\.location\s*=\s*'(https.+SAMLRequest=.+?)';`)
)

type aadClient struct {
	*baseClient
	tenantId string
	appId    string
}

// url is the 'User Access URL' found in the Properties screen of the Azure Enterprise Application
// which grants access to the AWS role(s).  Should look something like:
// https://myapps.microsoft.com/signin/<app name>/<app id>?tenantId=<tenant id>
// MFA is only supported for users at the organizational level; per-app conditional access policies
// requiring MFA are not supported.
func NewAadClient(url string) (*aadClient, error) {
	bc, err := newBaseClient(url)
	if err != nil {
		return nil, err
	}

	c := &aadClient{baseClient: bc}
	if err = c.parseTenantId(); err != nil {
		return nil, err
	}

	if err = c.parseAppId(); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *aadClient) Authenticate() error {
	return c.AuthenticateWithContext(context.Background())
}

// even speed-running through this without MFA, it takes around 6 seconds to process an aad-managed user,
// and 10 seconds to handle a federated user.  With all of the behind the scenes redirects and our response
// processing at multiple parts of the flow, I don't think this will get much faster.
//nolint:bodyclose // response bodies closed in parseResponse
func (c *aadClient) AuthenticateWithContext(ctx context.Context) error {
	req, _ := newHttpRequest(ctx, http.MethodGet, c.authUrl.String())
	res, err := checkResponseError(c.httpClient.Do(req.Request))
	if err != nil {
		return err
	}

	authRes := new(authResponse)
	if err = parseResponse(res.Body, authRes); err != nil {
		return err
	}

	if err = c.auth(ctx, authRes.LoginUrl(res.Request.URL), authRes); err != nil {
		return err
	}

	// A "keep me signed in" prompt may show up before getting to the good stuff. authRes.ErrCode should
	// equal 50058 too ... isn't really an error, other than signalling you've reached this KMSI prompt
	if strings.HasSuffix(authRes.UrlPost, "/kmsi") {
		kmsiUrl := authRes.LoginUrl(res.Request.URL)

		kmsiForm := url.Values{}
		kmsiForm.Set(authRes.FTName, authRes.FT)
		kmsiForm.Set("ctx", authRes.Ctx)
		kmsiForm.Set("LoginOptions", "1")

		req, _ = newHttpRequest(ctx, http.MethodPost, kmsiUrl.String())
		res, err = checkResponseError(c.httpClient.Do(req.withValues(kmsiForm).Request))
		if err != nil {
			return err
		}
	}

	// fixme - if we don't do kmsi, res.Body is closed by auth() and a 'read on closed response body' error happens here
	// KMSI or not, I think we end up here. Another JS auto-submit form containing OIDC stuff.
	// The OIDC ID token probably isn't sufficient for use with the IdentityToken* methods, since
	// there aren't any useful claims in the token, afaict just basic profile info.
	// However, this should be sufficient to say authentication is complete, if successful.
	_, err = c.submitResponse(res)
	return err
}

func (c *aadClient) Identity() (*identity.Identity, error) {
	return c.identity(aadIdentityProvider), nil
}

func (c *aadClient) IdentityToken() (*credentials.OidcIdentityToken, error) {
	return c.IdentityTokenWithContext(context.Background())
}

// todo - this is unverified.
func (c *aadClient) IdentityTokenWithContext(ctx context.Context) (*credentials.OidcIdentityToken, error) {
	oauthUrlBase := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0", c.tenantId)

	pkce, err := newPkceCode()
	if err != nil {
		return nil, err
	}
	authzQS := c.pkceAuthzRequest(pkce.Challenge())

	var vals url.Values
	vals, err = c.oauthAuthorize(fmt.Sprintf("%s/authorize", oauthUrlBase), authzQS, false)
	if err != nil {
		// reauth?
		return nil, err
	}

	if vals.Get("state") != authzQS.Get("state") {
		return nil, errOauthStateMismatch
	}

	token, err := c.oauthToken(fmt.Sprintf("%s/token", oauthUrlBase), vals.Get("code"), pkce.Verifier())
	if err != nil {
		return nil, err
	}

	return token.IdToken, nil
}

func (c *aadClient) SamlAssertion() (*credentials.SamlAssertion, error) {
	return c.SamlAssertionWithContext(context.Background())
}

func (c *aadClient) SamlAssertionWithContext(ctx context.Context) (*credentials.SamlAssertion, error) {
	// using c.authUrl directly won't work, you need to fetch that URL, then process the response which
	// contains the actual URL we need to submit (which is embedded in JS, because why wouldn't it be?).
	req, _ := newHttpRequest(ctx, http.MethodGet, c.authUrl.String())
	res, err := checkResponseError(c.httpClient.Do(req.Request))
	if err != nil {
		// We will see HTTP 200 even if the caller is unauthenticated, so any error here is probably something
		// attempting authentication won't help, just bail out.
		return nil, err
	}
	defer res.Body.Close()

	data, _ := ioutil.ReadAll(res.Body)
	match := samlRe.FindSubmatch(data)
	if match == nil || len(match) < 2 {
		// response is probably a login page, so attempt re-auth
		if err = c.AuthenticateWithContext(ctx); err != nil {
			return nil, err
		}
		return c.SamlAssertionWithContext(ctx)
	}

	u, _ := url.Parse(string(match[1]))
	if err = c.samlRequest(ctx, u); err != nil {
		return nil, err
	}

	return c.saml, nil
}

func (c *aadClient) parseTenantId() error {
	c.tenantId = c.authUrl.Query().Get("tenantId")
	if len(c.tenantId) < 1 {
		return errors.New("tenant ID not found in url")
	}
	return nil
}

func (c *aadClient) parseAppId() error {
	parts := strings.Split(c.authUrl.Path, `/`)
	c.appId = parts[len(parts)-1]
	if len(c.appId) < 1 {
		return errors.New("app ID not found in url")
	}
	return nil
}

func (c *aadClient) submitResponse(r *http.Response) (*http.Response, error) {
	defer r.Body.Close()

	doc, err := goquery.NewDocumentFromReader(r.Body)
	if err != nil {
		return nil, err
	}

	form := doc.Find("body form")
	formAction, ok := form.Attr("action")
	if !ok {
		return nil, errors.New("missing form submit url")
	}

	var submitUrl *url.URL
	submitUrl, err = url.Parse(formAction)
	if err != nil {
		return nil, err
	}

	if len(submitUrl.Scheme) < 1 {
		submitUrl = r.Request.URL.ResolveReference(submitUrl)
	}

	vals := url.Values{}
	form.Find("input").Each(func(i int, s *goquery.Selection) {
		var name, val string

		name, ok = s.Attr("name")
		if !ok {
			return
		}

		val, ok = s.Attr("value")
		if !ok {
			return
		}

		vals.Set(name, val)
	})

	req, _ := newHttpRequest(context.Background(), http.MethodPost, submitUrl.String())
	return checkResponseError(c.httpClient.Do(req.withValues(vals).Request))
}

//nolint:bodyclose // response bodies closed in parseResponse
func (c *aadClient) auth(ctx context.Context, authUrl *url.URL, authRes *authResponse) error {
	authForm := url.Values{}
	authForm.Set(authRes.FTName, authRes.FT)
	authForm.Set("ctx", authRes.Ctx)
	authForm.Set("login", c.Username)

	req, _ := newHttpRequest(ctx, http.MethodPost, authUrl.String())
	res, err := checkResponseError(c.httpClient.Do(req.withValues(authForm).Request))
	if err != nil {
		return err
	}

	if err = parseResponse(res.Body, authRes); err != nil {
		return err
	}

	// a bold assumption that everything down this path is not nil
	if u := authRes.CredentialTypeResult.Credentials.FederationRedirectUrl; len(u) > 0 {
		res, err = c.doFederatedAuth(u)
		if err != nil {
			return err
		}
	} else {
		// assume anything else means we're an aad-managed account
		// reset authRes.ErrCode so we capture the correct state of the authentication attempt
		authRes.ErrCode = ""

		if err = c.gatherCredentials(); err != nil {
			return err
		}
		authForm.Set("passwd", c.Password)

		// update existing req with new form values (password)
		res, err = checkResponseError(c.httpClient.Do(req.withValues(authForm).Request))
		if err != nil {
			return err
		}
	}

	// test for auth failure. Ideally auth failure for a federated user set 'err' and returned before this,
	// but we'll be safe and test everything. Code 50126 is bad username/password error
	if err = parseResponse(res.Body, authRes); err != nil {
		return err
	} else if authRes.ErrCode == strconv.Itoa(aadBadUserPassErrCode) {
		return errors.New("authentication failed")
	}

	// it is possible to require MFA for federated/guest users
	return c.checkMfa(ctx, authRes)
}

func (c *aadClient) doFederatedAuth(fedUrl string) (res *http.Response, err error) {
	cfg := AuthenticationClientConfig{
		CredentialInputProvider: c.CredentialInputProvider,
		MfaTokenProvider:        c.MfaTokenProvider,
		IdentityProviderName:    aadIdentityProvider,
		Logger:                  c.Logger,
		MfaType:                 MfaTypeAuto,
		Username:                c.Username,
		Password:                c.Password,
	}

	if len(c.FederatedUsername) > 0 {
		cfg.Username = c.FederatedUsername
	}

	// federation url must be one of the aws-runas supported external clients
	sc := MustGetSamlClient("", fedUrl, cfg)
	if err = sc.Authenticate(); err != nil {
		return nil, err
	}

	req, _ := newHttpRequest(context.Background(), http.MethodGet, fedUrl)
	res, err = checkResponseError(c.httpClient.Do(req.Request))
	if err != nil {
		return nil, err
	}

	return c.submitResponse(res)
}

//nolint:bodyclose // response bodies closed in parseResponse
func (c *aadClient) checkMfa(ctx context.Context, authRes *authResponse) error {
	var res *http.Response
	var err error

	if len(authRes.UrlSkipMfaRegistration) > 0 {
		// We can't register an MFA device here, so skip past it
		req, _ := newHttpRequest(ctx, http.MethodGet, authRes.UrlSkipMfaRegistration)
		res, err = checkResponseError(c.httpClient.Do(req.Request))
		if err != nil {
			return err
		}

		return parseResponse(res.Body, authRes)
	} else if len(authRes.UserProofs) > 0 {
		res, err = c.handleMfa(authRes)
		if err != nil {
			return err
		}

		return parseResponse(res.Body, authRes)
	}

	return nil
}

func (c *aadClient) handleMfa(authRes *authResponse) (*http.Response, error) {
	factor, err := c.findFactor(authRes.UserProofs)
	if err != nil {
		return nil, err
	}

	mfaReq := aadMfaRequest{
		AuthMethodId: factor.AuthMethodID,
		Method:       "BeginAuth",
		Ctx:          authRes.Ctx,
		FlowToken:    authRes.FT,
	}

	mfaRes := new(aadMfaResponse)
	if err = c.submitJson(authRes.UrlBeginAuth, mfaReq, mfaRes); err != nil {
		return nil, err
	}

	if !mfaRes.Success {
		return nil, errors.New("mfa failed")
	}

	mfaReq = aadMfaRequest{
		AuthMethodId: mfaRes.AuthMethodId,
		Method:       "EndAuth",
		Ctx:          mfaRes.Ctx,
		FlowToken:    mfaRes.FlowToken,
		SessionId:    mfaRes.SessionId,
	}

	wait := time.Duration(authRes.PerAuthPollingInterval[factor.AuthMethodID]) * time.Second
	if wait < 500*time.Millisecond {
		wait = 500 * time.Millisecond
	}

	switch c.MfaType {
	case MfaTypePush:
		fmt.Print("Waiting for Push MFA ")
		mfaRes, err = c.handlePushMfa(authRes.UrlEndAuth, mfaReq, wait)
	case MfaTypeCode:
		mfaRes, err = c.handleCodeMfa(authRes.UrlEndAuth, mfaReq, wait)
	}

	if err != nil {
		return nil, err
	}

	if !mfaRes.Success {
		return nil, errors.New("mfa failed")
	}

	vals := url.Values{}
	vals.Set(authRes.FTName, mfaRes.FlowToken)
	vals.Set("request", mfaRes.Ctx)
	vals.Set("login", c.Username)

	req, _ := newHttpRequest(context.Background(), http.MethodPost, authRes.LoginUrl(nil).String())
	return checkResponseError(c.httpClient.Do(req.withValues(vals).Request))
}

//nolint:gocognit,gocyclo // won't simplify
func (c *aadClient) findFactor(mfaCfg []aadUserProof) (aadUserProof, error) {
	factors := make([]aadUserProof, 0)

	switch c.MfaType {
	case MfaTypeAuto:
		for _, v := range mfaCfg {
			switch v.AuthMethodID {
			case mfaMethodNotify:
				c.MfaType = MfaTypePush
			case mfaMethodSMS, mfaMethodOTP:
				c.MfaType = MfaTypeCode
			}

			factors = append(factors, v)
			if v.IsDefault {
				break
			}
		}
	case MfaTypePush:
		// MS Authenticator app push notification
		for _, v := range mfaCfg {
			if v.AuthMethodID == mfaMethodNotify {
				factors = append(factors, v)
				if v.IsDefault {
					break
				}
			}
		}
	case MfaTypeCode:
		// TOTP, SMS
		for _, v := range mfaCfg {
			if v.AuthMethodID == mfaMethodOTP || v.AuthMethodID == mfaMethodSMS {
				factors = append(factors, v)
				if v.IsDefault {
					break
				}

			}
		}
	case MfaTypeNone:
		return aadUserProof{}, nil
	}

	if len(factors) < 1 {
		return aadUserProof{}, errMfaNotConfigured
	}

	// default factor should be last on the list, otherwise return the 1st element of the list
	if f := factors[len(factors)-1]; f.IsDefault {
		return f, nil
	}
	return factors[0], nil
}

func (c *aadClient) handleCodeMfa(mfaUrl string, mfaReq aadMfaRequest, wait time.Duration) (*aadMfaResponse, error) {
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

	mfaReq.AdditionalAuthData = c.MfaTokenCode

	res, err := c.sendMfaReply(mfaUrl, mfaReq)
	if err != nil {
		return nil, err
	}

	if res.Retry {
		c.MfaTokenCode = ""
		time.Sleep(wait)
		return c.handleCodeMfa(mfaUrl, mfaReq, wait)
	}

	return res, nil
}

func (c *aadClient) handlePushMfa(mfaUrl string, mfaReq aadMfaRequest, wait time.Duration) (*aadMfaResponse, error) {
	res, err := c.sendMfaReply(mfaUrl, mfaReq)
	if err != nil {
		return nil, err
	}

	if res.Retry {
		time.Sleep(wait)
		fmt.Print(".")
		return c.handlePushMfa(mfaUrl, mfaReq, wait)
	}

	return res, nil
}

func (c *aadClient) sendMfaReply(mfaUrl string, mfaReq aadMfaRequest) (*aadMfaResponse, error) {
	mfaRes := new(aadMfaResponse)
	if err := c.submitJson(mfaUrl, mfaReq, mfaRes); err != nil {
		return nil, err
	}

	if mfaRes.ErrCode == aadInvalidMfaCode {
		mfaRes.Retry = true
	} else if mfaRes.ErrCode != 0 {
		return nil, fmt.Errorf("mfa failure: %s [code: %d]", mfaRes.Message, mfaRes.ErrCode)
	}

	return mfaRes, nil
}

func (c *aadClient) submitJson(submitUrl string, inData interface{}, outData interface{}) error {
	mfaJson, err := json.Marshal(inData)
	if err != nil {
		return err
	}

	req, _ := newHttpRequest(context.Background(), http.MethodPost, submitUrl)
	req.withContentType(contentTypeJson).withBody(bytes.NewReader(mfaJson))

	var res *http.Response
	res, err = checkResponseError(c.httpClient.Do(req.Request))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(outData)
}

func checkResponseError(r *http.Response, err error) (*http.Response, error) {
	if err != nil {
		return nil, err
	} else if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %s (%d)", r.Status, r.StatusCode)
	}
	return r, err
}

func parseResponse(body io.ReadCloser, out interface{}) error {
	defer body.Close()

	data, err := ioutil.ReadAll(body)
	if err != nil {
		return err
	}

	match := bodyRe.FindSubmatch(data)
	if match == nil || len(match) < 2 {
		return errors.New("expected response content not found")
	}
	return json.Unmarshal(match[1], out)
}

type authResponse struct {
	Ctx          string         `json:"sCtx"`
	ErrCode      string         `json:"sErrorCode"`
	ErrTxt       string         `json:"sErrTxt"`
	FT           string         `json:"sFT"`
	FTName       string         `json:"sFTName"`
	UrlPost      string         `json:"urlPost"`
	UrlBeginAuth string         `json:"urlBeginAuth"`
	UrlEndAuth   string         `json:"urlEndAuth"`
	UserProofs   []aadUserProof `json:"arrUserProofs"`
	urlPost      *url.URL

	CredentialTypeResult   aadGetCredTypeResults `json:"oGetCredTypeResult"`
	PerAuthPollingInterval map[string]float64    `json:"oPerAuthPollingInterval"`
	UrlSkipMfaRegistration string                `json:"urlSkipMfaRegistration"`
}

func (r authResponse) LoginUrl(base *url.URL) *url.URL {
	if r.urlPost == nil {
		r.urlPost, _ = url.Parse(r.UrlPost)
	}

	if len(r.urlPost.Scheme) < 1 && base != nil {
		// turn relative url to absolute url
		return base.ResolveReference(r.urlPost)
	}
	return r.urlPost
}

type aadUserProof struct {
	AuthMethodID string `json:"authMethodId"`
	Data         string `json:"data"`
	Display      string `json:"display"`
	IsDefault    bool   `json:"isDefault"`
}

type aadGetCredTypeResults struct {
	Credentials aadCredDetails
}

type aadCredDetails struct {
	HasPassword           bool
	PrefCredential        int
	FederationRedirectUrl string
}

type aadMfaRequest struct {
	AuthMethodId       string
	Method             string
	Ctx                string
	FlowToken          string
	SessionId          string `json:",omitempty"`
	AdditionalAuthData string `json:",omitempty"`
}

type aadMfaResponse struct {
	Success       bool
	ResultValue   string
	Message       interface{}
	AuthMethodId  string
	ErrCode       int
	Retry         bool
	FlowToken     string
	Ctx           string
	SessionId     string
	CorrelationId string
	Timestamp     time.Time
}
