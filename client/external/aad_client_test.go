package external

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

var aadMock *httptest.Server

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
		// todo
	})
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
	c := newMockAadClient()
	c.Username = "samluser"
	c.Password = "whatever"
	// todo
}

func newMockAadClient() *aadClient {
	c := &aadClient{
		baseClient: new(baseClient),
		tenantId:   "12345",
		appId:      "54321",
	}
	c.authUrl, _ = url.Parse(aadMock.URL + "/myapp")
	c.httpClient = aadMock.Client()

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
		buf.WriteString(fmt.Sprintf("window.location='%s?SAMLRequest=mysamlrequest'", aadMock.URL))
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

func processMfaRequest(r io.Reader) (*aadMfaResponse, error) {
	body, err := ioutil.ReadAll(r)
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
	return []byte(fmt.Sprintf(body, j)), nil
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
