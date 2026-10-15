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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/mmmorris1975/aws-runas/shared"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

const aadMockPushNumber = 42

var (
	aadMock       *httptest.Server
	aadPushPolls  atomic.Int32
	aadPushNumber atomic.Int32
)

//nolint:gochecknoinits // too lazy to figure out a better way
func init() {
	mux := http.NewServeMux()
	mux.HandleFunc("/myapp", aadAppHandler)
	mux.HandleFunc("/login", aadLoginHandler)
	mux.HandleFunc("/kmsi", aadKmsiHandler)
	mux.HandleFunc("/authend", aadAuthEndHandler)
	mux.HandleFunc("/skipmfa", aadSkipMfaHandler)
	mux.HandleFunc("/beginmfa", aadBeginMfaHandler)
	mux.HandleFunc("/endmfa", aadEndMfaHandler)
	mux.HandleFunc("/mock/auth", aadMockFedIdpHandler)
	mux.HandleFunc("/samlredirect", aadSamlRedirectHandler)
	mux.HandleFunc("/samlresp", aadSamlResponseHandler)

	aadPushNumber.Store(aadMockPushNumber)
	aadMock = httptest.NewServer(mux)
}

func TestNewAadClient(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		u := "https://myapps.microsoft.com/signin/testapp/12345?tenantId=54321"
		c, err := NewAadClient(u)
		if err != nil {
			t.Error(err)
			return
		}

		if c.appId != "12345" || c.tenantId != "54321" {
			t.Error("unexpected app id or tenant id")
		}
	})

	t.Run("bad tenant", func(t *testing.T) {
		u := "https://myapps.microsoft.com/signin/testapp/12345"
		_, err := NewAadClient(u)
		if err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("bad app id", func(t *testing.T) {
		u := "https://myapps.microsoft.com/12345?tenantId=54321"
		_, err := NewAadClient(u)
		if err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestAadClient_Authenticate_Member(t *testing.T) {
	t.Run("no mfa", func(t *testing.T) {
		c := newMockAadClient()
		c.Username = "good"
		c.Password = "good"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("bad password", func(t *testing.T) {
		c := newMockAadClient()
		c.Username = "good"
		c.Password = "bad"

		if err := c.Authenticate(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("skip mfa", func(t *testing.T) {
		c := newMockAadClient()
		c.Username = "skipmfa"
		c.Password = "whatever"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("auto mfa", func(t *testing.T) {
		c := newMockAadClient()
		c.Username = "automfa"
		c.Password = "whatever"
		c.MfaType = MfaTypeAuto
		c.MfaTokenCode = "24680"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("code mfa", func(t *testing.T) {
		t.Run("good", func(t *testing.T) {
			c := newMockAadClient()
			c.Username = "codemfa"
			c.Password = "whatever"
			c.MfaType = MfaTypeCode
			c.MfaTokenCode = "24680"

			if err := c.Authenticate(); err != nil {
				t.Error(err)
				return
			}
		})

		t.Run("bad", func(t *testing.T) {
			c := newMockAadClient()
			c.Username = "codemfa"
			c.Password = "whatever"
			c.MfaType = MfaTypeCode

			if err := c.Authenticate(); err == nil {
				t.Error("did not receive expected error")
			}
		})
	})

	t.Run("push mfa", func(t *testing.T) {
		aadPushPolls.Store(0)
		c := newMockAadClient()
		c.Username = "pushmfa"
		c.Password = "whatever"
		c.MfaType = MfaTypePush

		out := captureStdout(t, func() {
			if err := c.Authenticate(); err != nil {
				t.Error(err)
			}
		})

		if !strings.Contains(out, fmt.Sprintf("Enter %d", aadMockPushNumber)) {
			t.Errorf("number matching prompt not displayed, got: %q", out)
		}
	})

	t.Run("push mfa without number matching", func(t *testing.T) {
		aadPushPolls.Store(0)
		aadPushNumber.Store(0)
		defer aadPushNumber.Store(aadMockPushNumber)

		c := newMockAadClient()
		c.Username = "pushmfa"
		c.Password = "whatever"
		c.MfaType = MfaTypePush

		out := captureStdout(t, func() {
			if err := c.Authenticate(); err != nil {
				t.Error(err)
			}
		})

		if strings.Contains(out, "Enter ") {
			t.Errorf("unexpected number matching prompt, got: %q", out)
		}
		if !strings.Contains(out, "Waiting for Push MFA confirmation") {
			t.Errorf("push prompt not displayed, got: %q", out)
		}
	})

	t.Run("saml response after mfa", func(t *testing.T) {
		c := newMockAadClient()
		c.Username = "samlaftermfa"
		c.Password = "whatever"
		c.MfaType = MfaTypeCode
		c.MfaTokenCode = "24680"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
			return
		}

		if c.saml == nil || len(*c.saml) < 1 {
			t.Error("SAML response was not captured")
		}
	})

	t.Run("no kmsi", func(t *testing.T) {
		c := newMockAadClient()
		c.Username = "nokmsi"
		c.Password = "whatever"

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})

	t.Run("prompted username", func(t *testing.T) {
		c := newMockAadClient()
		c.CredentialInputProvider = func(_, _ string) (string, string, error) {
			return "good", "good", nil
		}

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})
}

func TestAadClient_Authenticate_FederatedUnsupported(t *testing.T) {
	c := newMockAadClient()
	c.Username = "badfed"
	c.Password = "whatever"

	if err := c.Authenticate(); err == nil {
		t.Error("did not receive expected error")
	}
}

func TestAadClient_Authenticate_Guest(t *testing.T) {
	// only test guest user happy path, since all other activity is federated to external provider
	t.Run("good", func(t *testing.T) {
		c := newMockAadClient()
		c.Username = "guest"
		c.Password = "whatever"
		c.FederatedUsername = "myfed" // only required in special configurations

		if err := c.Authenticate(); err != nil {
			t.Error(err)
		}
	})
}

func TestAadClient_Identity(t *testing.T) {
	u := "https://myapps.microsoft.com/signin/testapp/12345?tenantId=54321"
	c, err := NewAadClient(u)
	if err != nil {
		t.Error(err)
		return
	}

	// never errors
	id, _ := c.Identity()
	if id.Provider != aadIdentityProvider {
		t.Error("unexpected Provider name")
	}
}

func TestAadClient_IdentityToken(t *testing.T) {
	c := newMockAadClient()
	c.Username = "oidcuser"
	c.Password = "whatever"
	// todo
}

func TestAadClient_SamlAssertion(t *testing.T) {
	t.Run("script redirect", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/samljs", func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintf(w, "<html><script>window.location='https://%s/samlresp?SAMLRequest=mysamlrequest';</script></html>", r.Host)
		})
		mux.HandleFunc("/samlresp", aadSamlResponseHandler)

		srv := httptest.NewTLSServer(mux)
		defer srv.Close()

		c := newMockAadClient()
		c.httpClient = srv.Client()
		c.authUrl, _ = url.Parse(srv.URL + "/samljs")

		saml, err := c.SamlAssertion()
		if err != nil {
			t.Error(err)
			return
		}

		if saml == nil || len(*saml) < 1 {
			t.Error("empty SAML assertion")
		}
	})

	t.Run("http redirect", func(t *testing.T) {
		c := newMockAadClient()
		c.authUrl, _ = url.Parse(aadMock.URL + "/samlredirect")

		saml, err := c.SamlAssertion()
		if err != nil {
			t.Error(err)
			return
		}

		if saml == nil || len(*saml) < 1 {
			t.Error("empty SAML assertion")
		}
	})

	t.Run("no saml request after authentication", func(t *testing.T) {
		c := newMockAadClient()
		c.Username = "good"
		c.Password = "good"

		if _, err := c.SamlAssertion(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func newMockAadClient() *aadClient {
	c := &aadClient{
		baseClient: new(baseClient),
		tenantId:   "12345",
		appId:      "54321",
	}
	c.authUrl, _ = url.Parse(aadMock.URL + "/myapp")
	c.httpClient = aadMock.Client()
	c.Logger = new(shared.DefaultLogger)

	return c
}

func aadAppHandler(w http.ResponseWriter, _ *http.Request) {
	ar := aadAuthResponse{
		Ctx:     "myctx",
		FT:      "myftoken",
		FTName:  "flow_token",
		UrlPost: "/login",
	}

	body, _ := genAuthResponse(ar)
	_, _ = w.Write(body)
}

func aadLoginHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	ar := aadAuthResponse{
		Ctx:    "myctx",
		FT:     "myftoken",
		FTName: "flow_token",
	}

	switch r.PostFormValue("login") {
	case "good":
		ar.ErrCode = strconv.Itoa(aadBadUserPassErrCode)
		if pw := r.PostFormValue("passwd"); pw == "good" {
			ar.ErrCode = "0"
			ar.UrlPost = "/kmsi"
		}
	case "samlaftermfa":
		if r.PostFormValue(ar.FTName) == "mfa complete" {
			aadSamlResponseHandler(w, r)
			return
		}
		ar.UserProofs = []aadUserProof{{AuthMethodID: aadMfaMethodOTP, IsDefault: true}}
		ar.UrlBeginAuth = fmt.Sprintf("%s/beginmfa", aadMock.URL)
		ar.UrlEndAuth = fmt.Sprintf("%s/endmfa", aadMock.URL)
		ar.UrlPost = fmt.Sprintf("%s/login", aadMock.URL)
	case "nokmsi":
		if r.PostFormValue("passwd") != "" {
			body, _ := genAuthResponse(ar)
			form, _ := genFormResponse("/authend", map[string]string{"a": "1"})
			_, _ = w.Write(append(body, form...))
			return
		}
	case "badfed":
		ar.CredentialTypeResult = aadGetCredTypeResults{Credentials: aadCredDetails{
			HasPassword:           true,
			PrefCredential:        1,
			FederationRedirectUrl: "https://unsupported-idp.invalid/sso",
		}}
	case "skipmfa":
		ar.UrlSkipMfaRegistration = fmt.Sprintf("%s/skipmfa", aadMock.URL)
	case "automfa", "codemfa":
		ar.UrlPost = "/kmsi"

		if r.PostFormValue(ar.FTName) != "mfa complete" {
			ar.UserProofs = []aadUserProof{
				{AuthMethodID: aadMfaMethodNotify, IsDefault: false},
				{AuthMethodID: aadMfaMethodSMS, IsDefault: false},
				{AuthMethodID: aadMfaMethodOTP, IsDefault: true},
			}
			ar.UrlBeginAuth = fmt.Sprintf("%s/beginmfa", aadMock.URL)
			ar.UrlEndAuth = fmt.Sprintf("%s/endmfa", aadMock.URL)
			ar.UrlPost = fmt.Sprintf("%s/login", aadMock.URL)
		}
	case "pushmfa":
		ar.UrlPost = "/kmsi"

		if r.PostFormValue(ar.FTName) != "mfa complete" {
			ar.UserProofs = []aadUserProof{
				{AuthMethodID: aadMfaMethodNotify, IsDefault: true},
				{AuthMethodID: aadMfaMethodSMS, IsDefault: false},
				{AuthMethodID: aadMfaMethodOTP, IsDefault: false},
			}
			ar.UrlBeginAuth = fmt.Sprintf("%s/beginmfa", aadMock.URL)
			ar.UrlEndAuth = fmt.Sprintf("%s/endmfa", aadMock.URL)
			ar.UrlPost = fmt.Sprintf("%s/login", aadMock.URL)
		}
	case "guest":
		ar.CredentialTypeResult = aadGetCredTypeResults{Credentials: aadCredDetails{
			HasPassword:           true,
			PrefCredential:        1,
			FederationRedirectUrl: fmt.Sprintf("%s/mock/auth", aadMock.URL),
		}}
	case "samluser":
		ar.UrlPost = "/kmsi"
		body, _ := genAuthResponse(ar)
		buf := bytes.NewBuffer(body)
		_, _ = fmt.Fprintf(buf, "window.location='%s?SAMLRequest=mysamlrequest'", aadMock.URL)
		_, _ = w.Write(buf.Bytes())
		return
	}

	body, _ := genAuthResponse(ar)
	_, _ = w.Write(body)
}

func aadKmsiHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	if v := r.PostFormValue("LoginOptions"); v != "1" {
		http.Error(w, "invalid login option", http.StatusBadRequest)
	}

	// form hidden input values can be anything, we're not handling them
	body, err := genFormResponse("/authend", map[string]string{"a": "1"})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(body)
}

func aadAuthEndHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	_, _ = w.Write(nil)
}

func aadMockFedIdpHandler(w http.ResponseWriter, _ *http.Request) {
	// returns a form which will get submitted to get the auth response data
	body, _ := genFormResponse("/skipmfa", map[string]string{})
	_, _ = w.Write(body)
}

func aadSkipMfaHandler(w http.ResponseWriter, _ *http.Request) {
	ar := aadAuthResponse{
		Ctx:     "myctx",
		FT:      "myftoken",
		FTName:  "flow_token",
		UrlPost: "/kmsi",
	}

	body, _ := genAuthResponse(ar)
	_, _ = w.Write(body)
}

func aadBeginMfaHandler(w http.ResponseWriter, r *http.Request) {
	mfaRes, err := processMfaRequest(r.Body)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if mfaRes.AuthMethodId == aadMfaMethodNotify {
		mfaRes.Entropy = int(aadPushNumber.Load())
	}

	j, _ := json.Marshal(mfaRes)
	_, _ = w.Write(j)
}

func aadEndMfaHandler(w http.ResponseWriter, r *http.Request) {
	mfaRes, err := processMfaRequest(r.Body)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	switch mfaRes.AuthMethodId {
	case aadMfaMethodNotify:
		mfaRes.Retry = true
		mfaRes.Success = false

		if aadPushPolls.Add(1) >= 2 {
			mfaRes.Success = true
			mfaRes.Retry = false
		}
	case aadMfaMethodOTP, aadMfaMethodSMS:
		// the otp code is contained in the AdditionalAuthData of the request, which is being processed through
		// processMfaRequest() and returning the value in the mfaRes.Message field, which is non-standard
		if mfaRes.Message == nil || mfaRes.Message != "24680" {
			mfaRes.Success = false
			mfaRes.Message = "incorrect mfa code"
		}
	default:
		mfaRes.Success = false
		mfaRes.Message = "unsupported mfa type"
	}

	j, _ := json.Marshal(mfaRes)
	_, _ = w.Write(j)
}

func aadSamlRedirectHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/samlresp?SAMLRequest=mysamlrequest", http.StatusFound)
}

func aadSamlResponseHandler(w http.ResponseWriter, _ *http.Request) {
	doc := `<Assertion><Attribute Name="https://aws.amazon.com/SAML/Attributes/Role"><AttributeValue>` +
		`arn:aws:iam::123456789012:saml-provider/p,arn:aws:iam::123456789012:role/r</AttributeValue></Attribute></Assertion>`

	body, _ := genFormResponse("https://signin.aws.amazon.com/saml",
		map[string]string{"SAMLResponse": base64.StdEncoding.EncodeToString([]byte(doc))})
	_, _ = w.Write(body)
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()
	_ = w.Close()

	return <-done
}

func processMfaRequest(r io.Reader) (*aadMfaResponse, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	mfaRes := new(aadMfaResponse)
	mfaReq := new(aadMfaRequest)
	if err := json.Unmarshal(body, mfaReq); err != nil || len(mfaReq.AuthMethodId) < 1 {
		mfaRes.Success = false
		mfaRes.Message = "malformed request"
		return mfaRes, nil
	}

	mfaRes.Ctx = mfaReq.Ctx
	mfaRes.FlowToken = "mfa complete"
	mfaRes.SessionId = mfaReq.SessionId
	mfaRes.AuthMethodId = mfaReq.AuthMethodId
	mfaRes.Success = true
	mfaRes.Message = mfaReq.AdditionalAuthData // non-standard, but I want to pass the OTP code back

	return mfaRes, nil
}

func genAuthResponse(ar aadAuthResponse) ([]byte, error) {
	j, err := json.Marshal(ar)
	if err != nil {
		return nil, err
	}

	body := `
<html>
<head>
<script>
$Config=%s;
</script>
</head>
<body></body>
</html>
`
	return fmt.Appendf(nil, body, j), nil
}

func genFormResponse(actionUrl string, fields map[string]string) ([]byte, error) {
	formData := struct {
		Url    string
		Fields map[string]string
	}{
		Url:    actionUrl,
		Fields: fields,
	}

	body := `
<html>
<body>
<form action="{{.Url}}" method="post">
{{- range $k, $v := .Fields}}
  <input type="hidden" name="{{$k}}" value="{{$v}}">
{{- end}}
</form>
</body>
</html>
`

	out := new(bytes.Buffer)
	tmpl := template.Must(template.New("form").Parse(body))
	if err := tmpl.Execute(out, formData); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
