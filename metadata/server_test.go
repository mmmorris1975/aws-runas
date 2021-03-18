package metadata

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/mmmorris1975/aws-runas/client"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
	"github.com/mmmorris1975/aws-runas/shared"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewMetadataCredentialService(t *testing.T) {
	t.Run("empty addr", func(t *testing.T) {
		mcs, err := NewMetadataCredentialService("", new(Options))
		if err != nil {
			t.Error("did not receive expected error")
			return
		}

		if mcs.Addr() == nil {
			t.Error("invalid listener address")
		}
	})

	t.Run("nil options", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Error("did not receive expected panic")
			}
		}()

		_, _ = NewMetadataCredentialService("", nil)
	})

	t.Run("empty options", func(t *testing.T) {
		mcs, err := NewMetadataCredentialService(":0", new(Options))
		if err != nil {
			t.Error("did not receive expected error")
			return
		}

		if mcs.Addr() == nil {
			t.Error("invalid listener address")
		}
	})

	t.Run("good", func(t *testing.T) {
		o := &Options{
			Path:        "/mock",
			Profile:     "mock",
			Logger:      new(shared.DefaultLogger),
			AwsLogLevel: "",
		}

		mcs, err := NewMetadataCredentialService(":0", o)
		if err != nil {
			t.Error(err)
		}

		if mcs.Addr() == nil {
			t.Error("invalid listener address")
		}
	})
}

func TestMetadataCredentialService_Run(t *testing.T) {
	t.Skip("not testable")
}

func TestMetadataCredentialService_RunHeadless(t *testing.T) {
	t.Skip("not testable")
}

func TestMetadataCredentialService_profileHandler(t *testing.T) {
	mcs := mockMetadataCredentialService()

	t.Run("update", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, profilePath, bytes.NewBufferString("mockUpdate"))

		mcs.awsClient = new(mockAwsClient)
		mcs.profileHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("unexpected http status: %d", rec.Code)
		}

		if mcs.awsConfig.ProfileName != "mockUpdate" {
			t.Error("profile was not updated")
		}
	})

	t.Run("fetch", func(t *testing.T) {
		cfg, _ := mcs.configResolver.Config("mock")
		mcs.awsConfig = cfg

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, profilePath, http.NoBody)

		mcs.profileHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("unexpected http status: %d", rec.Code)
		}

		buf := make([]byte, rec.Body.Len())
		_, _ = rec.Body.Read(buf)

		// expect something that resembles a json object
		if !bytes.HasPrefix(buf, []byte(`{`)) || !bytes.HasSuffix(buf, []byte(`}`)) {
			t.Error("profile retrieval failed")
		}
	})

	t.Run("no config", func(t *testing.T) {
		mcs.awsConfig = nil

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, profilePath, http.NoBody)

		mcs.profileHandler(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("unexpected http status: %d", rec.Code)
		}
	})

	t.Run("bad config", func(t *testing.T) {
		cfg := mockConfigResolver(true)
		mcs.configResolver = &cfg

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, profilePath, bytes.NewBufferString("mockUpdate"))

		mcs.profileHandler(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("unexpected http status: %d", rec.Code)
		}
	})
}

func TestMetadataCredentialService_imdsV2TokenHandler(t *testing.T) {
	mcs := mockMetadataCredentialService()

	t.Run("unsupported method", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, imdsTokenPath, http.NoBody)

		mcs.imdsV2TokenHandler(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("unexpected http status code: %d", rec.Code)
		}
	})

	t.Run("missing header", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, imdsTokenPath, http.NoBody)

		mcs.imdsV2TokenHandler(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("unexpected http status code: %d", rec.Code)
		}
	})

	t.Run("bad header", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, imdsTokenPath, http.NoBody)
		req.Header.Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "-1")

		mcs.imdsV2TokenHandler(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("unexpected http status code: %d", rec.Code)
		}
	})

	t.Run("good", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, imdsTokenPath, http.NoBody)
		req.Header.Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "1800")

		mcs.imdsV2TokenHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("unexpected http status code: %d", rec.Code)
		}

		if rec.Body.Len() < 15 {
			t.Errorf("invalid token length: %d", rec.Body.Len())
		}
	})
}

func TestMetadataCredentialService_ec2CredHandler(t *testing.T) {
	mcs := mockMetadataCredentialService()

	cfg, _ := mcs.configResolver.Config("mock")
	mcs.awsConfig = cfg

	t.Run("first call", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, ec2CredPath, http.NoBody)

		mcs.ec2CredHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("unexpected http status code: %d", rec.Code)
			return
		}

		buf := make([]byte, rec.Body.Len())
		_, _ = rec.Body.Read(buf)

		if string(buf) != cfg.ProfileName {
			t.Errorf("did not receive expected profile name")
		}
	})

	t.Run("second call good", func(t *testing.T) {
		mcs.awsClient = new(mockAwsClient)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("%s%s", ec2CredPath, cfg.ProfileName), http.NoBody)

		mcs.ec2CredHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("unexpected http status code: %d", rec.Code)
			return
		}

		buf := make([]byte, rec.Body.Len())
		_, _ = rec.Body.Read(buf)

		var creds map[string]string
		if err := json.Unmarshal(buf, &creds); err != nil {
			t.Error(err)
			return
		}

		if creds["Code"] != "Success" || creds["Type"] != "AWS-HMAC" {
			t.Error("invalid credentials")
		}
	})

	t.Run("second call bad", func(t *testing.T) {
		c := mockAwsClient(true)
		mcs.awsClient = &c

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("%s%s", ec2CredPath, cfg.ProfileName), http.NoBody)

		mcs.ec2CredHandler(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("unexpected http status code: %d", rec.Code)
			return
		}
	})
}

func TestMetadataCredentialService_ecsCredHandler(t *testing.T) {
	mcs := mockMetadataCredentialService()
	mcs.options = &Options{Path: DefaultEcsCredPath}

	t.Run("good", func(t *testing.T) {
		mcs.awsClient = new(mockAwsClient)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, mcs.options.Path, http.NoBody)

		mcs.ecsCredHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("unexpected http status code: %d", rec.Code)
			return
		}

		buf := make([]byte, rec.Body.Len())
		_, _ = rec.Body.Read(buf)

		var creds map[string]string
		if err := json.Unmarshal(buf, &creds); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("with profile", func(t *testing.T) {
		mcs.awsClient = new(mockAwsClient)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, mcs.options.Path+"/my_profile", http.NoBody)

		mcs.ecsCredHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("unexpected http status code: %d", rec.Code)
			return
		}

		buf := make([]byte, rec.Body.Len())
		_, _ = rec.Body.Read(buf)

		var creds map[string]string
		if err := json.Unmarshal(buf, &creds); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("bad", func(t *testing.T) {
		c := mockAwsClient(true)
		mcs.awsClient = &c

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)

		mcs.ecsCredHandler(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("unexpected http status code: %d", rec.Code)
			return
		}
	})
}

func TestMetadataCredentialService_refreshHandler(t *testing.T) {
	mcs := mockMetadataCredentialService()

	t.Run("unsupported method", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, refreshPath, http.NoBody)

		mcs.refreshHandler(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("unexpected http status code: %d", rec.Code)
		}
	})

	t.Run("nil client", func(t *testing.T) {
		mcs.awsClient = nil
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, refreshPath, http.NoBody)

		mcs.refreshHandler(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("unexpected http status code: %d", rec.Code)
		}
	})

	t.Run("good", func(t *testing.T) {
		cfg, _ := mcs.configResolver.Config("mock")
		c, _ := mcs.clientFactory.Get(cfg)
		mcs.awsClient = c

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, refreshPath, http.NoBody)

		mcs.refreshHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("unexpected http status code: %d", rec.Code)
		}
	})

	t.Run("bad", func(t *testing.T) {
		c := mockAwsClient(true)
		mcs.awsClient = &c

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, refreshPath, http.NoBody)

		mcs.refreshHandler(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("unexpected http status code: %d", rec.Code)
		}
	})
}

func TestMetadataCredentialService_listRolesHandler(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		cfgFile := filepath.Join(t.TempDir(), "config")
		f, err := os.Create(cfgFile)
		if err != nil {
			t.Error(err)
			return
		}
		defer f.Close()

		if _, err = f.Write([]byte(testConfig)); err != nil {
			t.Error(err)
			return
		}

		_ = os.Setenv("AWS_CONFIG_FILE", cfgFile)
		defer os.Unsetenv("AWS_CONFIG_FILE")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, listRolesPath, http.NoBody)

		mockMetadataCredentialService().listRolesHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("unexpected http status code: %d", rec.Code)
			return
		}

		var body []string
		if err = json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Error(err)
			return
		}

		if len(body) < 2 {
			t.Error("did not find any roles")
		}
	})

	t.Run("bad", func(t *testing.T) {
		_ = os.Setenv("AWS_CONFIG_FILE", "cfgFile")
		defer os.Unsetenv("AWS_CONFIG_FILE")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, listRolesPath, http.NoBody)

		mockMetadataCredentialService().listRolesHandler(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("unexpected http status code: %d", rec.Code)
			return
		}
	})
}

//nolint:misspell  // it's a joke, son!
// for teh coverage gainz!!
func TestMetadataCredentialService_installSigHandler(t *testing.T) {
	installSigHandler(httptest.NewServer(nil).Config, new(net.TCPListener))
}

func TestMetadataCredentialService_logHandler(t *testing.T) {
	h := logHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("mock", "test")
		http.Error(w, "success", http.StatusTeapot)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)

	h(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("unexpected http status code: %d", rec.Code)
	}

	if rec.Header().Get("mock") != "test" {
		t.Error("missing header")
	}

	if !bytes.Equal(rec.Body.Bytes(), []byte("success\n")) {
		t.Error("invalid body")
	}
}

func TestMetadataCredentialService_rootHandler(t *testing.T) {
	t.Run("index", func(t *testing.T) {
		for _, v := range []string{"/", "/index.html", "/index.htm"} {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, v, http.NoBody)

			mockMetadataCredentialService().rootHandler(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("unexpected http status code: %d", rec.Code)
				return
			}

			if ct := rec.Header().Get("Content-Type"); ct != "text/html" {
				t.Errorf("invalid content-type '%s", ct)
			}

			if rec.Body.Len() < 1000 {
				t.Error("too short")
			}
		}
	})

	t.Run("css", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/site.css", http.NoBody)

		mockMetadataCredentialService().rootHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("unexpected http status code: %d", rec.Code)
			return
		}

		if ct := rec.Header().Get("Content-Type"); ct != "text/css" {
			t.Errorf("invalid content-type '%s", ct)
		}

		if rec.Body.Len() < 1000 {
			t.Error("too short")
		}
	})

	t.Run("js", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/site.js", http.NoBody)

		mockMetadataCredentialService().rootHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("unexpected http status code: %d", rec.Code)
			return
		}

		if ct := rec.Header().Get("Content-Type"); ct != "application/javascript" {
			t.Errorf("invalid content-type '%s", ct)
		}

		if rec.Body.Len() < 1000 {
			t.Error("too short")
		}
	})

	t.Run("invalid", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/bogus", http.NoBody)

		mockMetadataCredentialService().rootHandler(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("unexpected http status code: %d", rec.Code)
			return
		}
	})
}

// each of these methods fetch AWS credentials as their final step. Since we can't mock the STS endpoints from here,
// these aren't testable.
/*
func TestMetadataCredentialService_authHandler(t *testing.T) {
	rec := httptest.NewRecorder()

	body := url.Values{}
	body.Set("username", "test")
	body.Set("password", "test")
	req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	mcs := mockMetadataCredentialService()
	mcs.awsConfig = new(config.AwsConfig)
	mcs.clientOptions = new(client.Options)
	mcs.authHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("unexpected http status code: %d", rec.Code)
		return
	}
}

func TestMetadataCredentialService_mfaHandler(t *testing.T) {
	rec := httptest.NewRecorder()

	body := url.Values{}
	body.Set("mfa", "1234567")
	req := httptest.NewRequest(http.MethodPost, "/mfa", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	mcs := mockMetadataCredentialService()
	mcs.awsConfig = new(config.AwsConfig)
	mcs.mfaHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("unexpected http status code: %d", rec.Code)
		return
	}
}
*/

func TestMetadataCredentialService_customProfileHandler(t *testing.T) {
	t.Run("post", func(t *testing.T) {
		t.Run("iam", func(t *testing.T) {
			rec := httptest.NewRecorder()

			body := url.Values{}
			body.Set("adv-type", "iam")
			body.Set("role-arn", "arn:aws:iam:0123456789:role/test")
			body.Set("external-id", "test123")
			req := httptest.NewRequest(http.MethodPost, "/profile/custom", strings.NewReader(body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			mcs := mockMetadataCredentialService()
			mcs.awsConfig = new(config.AwsConfig)
			mcs.customProfileHandler(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("unexpected http status code: %d", rec.Code)
				return
			}
		})

		t.Run("saml", func(t *testing.T) {
			rec := httptest.NewRecorder()

			body := url.Values{}
			body.Set("adv-type", "saml")
			body.Set("role-arn", "arn:aws:iam:0123456789:role/test")
			body.Set("username", "testsaml")
			body.Set("password", "saml!password")
			body.Set("auth-url", "https://saml.local")
			req := httptest.NewRequest(http.MethodPost, "/profile/custom", strings.NewReader(body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			mcs := mockMetadataCredentialService()
			mcs.awsConfig = new(config.AwsConfig)
			mcs.customProfileHandler(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("unexpected http status code: %d", rec.Code)
				return
			}
		})

		t.Run("oidc", func(t *testing.T) {
			rec := httptest.NewRecorder()

			body := url.Values{}
			body.Set("adv-type", "oidc")
			body.Set("role-arn", "arn:aws:iam:0123456789:role/test")
			body.Set("username", "testoidc")
			body.Set("password", "oidc!password")
			body.Set("auth-url", "https://oidc.local")
			body.Set("client-id", "xx")
			body.Set("redirect-uri", "app:/callback")
			req := httptest.NewRequest(http.MethodPost, "/profile/custom", strings.NewReader(body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			mcs := mockMetadataCredentialService()
			mcs.awsConfig = new(config.AwsConfig)
			mcs.customProfileHandler(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("unexpected http status code: %d", rec.Code)
				return
			}
		})
	})

	t.Run("put", func(t *testing.T) {
		var err error
		var tmpCfg, tmpCred *os.File

		tmpCfg, err = os.CreateTemp(t.TempDir(), "config")
		if err != nil {
			t.Error(err)
			return
		}
		defer os.Remove(tmpCfg.Name())

		tmpCred, err = os.CreateTemp(t.TempDir(), "credentials")
		if err != nil {
			t.Error(err)
			return
		}
		defer os.Remove(tmpCred.Name())

		os.Setenv("AWS_CONFIG_FILE", tmpCfg.Name())
		os.Setenv("AWS_SHARED_CREDENTIALS_FILE", tmpCred.Name())
		defer func() {
			os.Unsetenv("AWS_CONFIG_FILE")
			os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")
		}()

		t.Run("iam", func(t *testing.T) {
			rec := httptest.NewRecorder()

			body := url.Values{}
			body.Set("adv-type", "iam")
			body.Set("role-arn", "arn:aws:iam:0123456789:role/test")
			body.Set("external-id", "test123")
			body.Set("profile-name", "test-iam")
			req := httptest.NewRequest(http.MethodPut, "/profile/custom", strings.NewReader(body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			mcs := mockMetadataCredentialService()
			mcs.awsConfig = new(config.AwsConfig)
			mcs.customProfileHandler(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("unexpected http status code: %d", rec.Code)
				return
			}
		})

		t.Run("saml", func(t *testing.T) {
			rec := httptest.NewRecorder()

			body := url.Values{}
			body.Set("adv-type", "saml")
			body.Set("role-arn", "arn:aws:iam:0123456789:role/test")
			body.Set("username", "testsaml")
			body.Set("password", "saml!password")
			body.Set("auth-url", "https://saml.local")
			body.Set("profile-name", "test-saml")
			req := httptest.NewRequest(http.MethodPut, "/profile/custom", strings.NewReader(body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			mcs := mockMetadataCredentialService()
			mcs.awsConfig = new(config.AwsConfig)
			mcs.customProfileHandler(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("unexpected http status code: %d", rec.Code)
				return
			}
		})

		t.Run("oidc", func(t *testing.T) {
			rec := httptest.NewRecorder()

			body := url.Values{}
			body.Set("adv-type", "oidc")
			body.Set("role-arn", "arn:aws:iam:0123456789:role/test")
			body.Set("username", "testoidc")
			body.Set("password", "oidc!password")
			body.Set("auth-url", "https://oidc.local")
			body.Set("client-id", "xx")
			body.Set("redirect-uri", "app:/callback")
			body.Set("profile-name", "test-oidc")
			req := httptest.NewRequest(http.MethodPut, "/profile/custom", strings.NewReader(body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			mcs := mockMetadataCredentialService()
			mcs.awsConfig = new(config.AwsConfig)
			mcs.customProfileHandler(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("unexpected http status code: %d", rec.Code)
				return
			}
		})
	})
}

func Test_cleanup(t *testing.T) {
	// just here for some test coverage numbers
	cleanup(new(http.Server), new(net.TCPListener))
}

func Test_handleAuthError(t *testing.T) {
	s := mockMetadataCredentialService()

	t.Run("MFA", func(t *testing.T) {
		w := httptest.NewRecorder()
		err := NewWebAuthenticationError()
		s.handleAuthError(err, w)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("unexpected http status %d", w.Code)
		}

		if h := w.Header().Get("X-AwsRunas-Authentication-Type"); h != err.Error() {
			t.Errorf("missing/unexpected header value: '%s'", h)
		}
	})

	t.Run("Auth", func(t *testing.T) {
		t.Run("no user", func(t *testing.T) {
			w := httptest.NewRecorder()
			err := NewWebAuthenticationError()
			s.handleAuthError(err, w)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("unexpected http status %d", w.Code)
			}

			if h := w.Header().Get("X-AwsRunas-Authentication-Type"); h != err.Error() {
				t.Errorf("missing/unexpected header value: '%s'", h)
			}
		})

		t.Run("with user", func(t *testing.T) {
			defer func() { s.awsConfig = new(config.AwsConfig) }()

			s.awsConfig = &config.AwsConfig{SamlUsername: "mock"}
			w := httptest.NewRecorder()
			err := NewWebAuthenticationError()
			s.handleAuthError(err, w)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("unexpected http status %d", w.Code)
			}

			if h := w.Header().Get("X-AwsRunas-Authentication-Type"); h != err.Error() {
				t.Errorf("missing/unexpected header value: '%s'", h)
			}

			if !bytes.Contains(w.Body.Bytes(), []byte("mock")) {
				t.Error("did not receive expected body content")
			}
		})
	})

	t.Run("other", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleAuthError(errors.New("other"), w)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("unexpected http status %d", w.Code)
		}
	})
}

func Test_listProfilesHandler(t *testing.T) {
	defer os.Unsetenv("AWS_CONFIG_FILE")
	os.Setenv("AWS_CONFIG_FILE", "../testdata/aws_config")

	s := mockMetadataCredentialService()
	w := httptest.NewRecorder()
	s.listProfilesHandler(w, nil)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected http status code: %d", w.Code)
	}

	data := make([]string, 0)
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Error(err)
	}

	if len(data) < 1 {
		t.Error("received empty profile list")
	}
}

func mockMetadataCredentialService() *metadataCredentialService {
	mcs := new(metadataCredentialService)
	mcs.configResolver = new(mockConfigResolver)

	factoryOptions := client.DefaultOptions
	factoryOptions.EnableCache = false
	factoryOptions.AwsLogLevel = ""
	factoryOptions.Logger = new(shared.DefaultLogger)
	factoryOptions.CommandCredentials = new(config.AwsCredentials)

	mcs.clientFactory = client.NewClientFactory(mcs.configResolver, factoryOptions)

	mcs.options = new(Options)
	mcs.options.Logger = factoryOptions.Logger
	mcs.options.AwsLogLevel = factoryOptions.AwsLogLevel

	return mcs
}

type mockConfigResolver bool

func (m *mockConfigResolver) Config(profile string) (*config.AwsConfig, error) {
	if *m {
		return nil, errors.New("error")
	}

	return &config.AwsConfig{
		Region:       "us-east-1",
		SamlUrl:      "https://mock.local/saml",
		SamlUsername: "mockUser",
		SamlProvider: "mock",
		ProfileName:  profile,
	}, nil
}

func (m *mockConfigResolver) Credentials(string) (*config.AwsCredentials, error) {
	if *m {
		return nil, errors.New("error")
	}

	return &config.AwsCredentials{
		SamlPassword:        "",
		WebIdentityPassword: "",
	}, nil
}

type mockAwsClient bool

func (m *mockAwsClient) Identity() (*identity.Identity, error) {
	return new(identity.Identity), nil
}

func (m *mockAwsClient) Roles() (*identity.Roles, error) {
	return new(identity.Roles), nil
}

func (m *mockAwsClient) Credentials() (*credentials.Credentials, error) {
	return m.CredentialsWithContext(context.Background())
}

func (m *mockAwsClient) CredentialsWithContext(context.Context) (*credentials.Credentials, error) {
	if *m {
		return nil, errors.New("error")
	}

	creds := &credentials.Credentials{
		AccessKeyId:     "mockAK",
		SecretAccessKey: "mockSK",
		Token:           "mockToken",
		Expiration:      time.Now().Add(30 * time.Minute),
		ProviderName:    "mock",
	}
	return creds, nil
}

func (m *mockAwsClient) ConfigProvider() aws.Config {
	return aws.Config{}
}

func (m *mockAwsClient) ClearCache() error {
	if *m {
		return errors.New("error")
	}
	return nil
}

var testConfig = `[default]

[profile norole]

[profile role1]
role_arn = arn:aws:iam::0123456789:role/role1

[profile x]

[role2]
role_arn = arn:aws:iam::0123456789:role/role2
`
