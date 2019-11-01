package metadata

import (
	cfglib "aws-runas/lib/config"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/mmmorris1975/aws-config/config"
	"github.com/mmmorris1975/simple-logger"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("AWS_CONFIG_FILE", "../../.aws/config")
	profile = "circle-role"
	log = simple_logger.StdLogger

	var err error
	cfg, err = config.NewAwsConfigResolver(nil)
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(m.Run())
}

func TestWriteResponse(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	t.Run("empty body", func(t *testing.T) {
		w := httptest.NewRecorder()
		writeResponse(w, r, "", http.StatusOK)

		res := w.Result()
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Error("bad status code")
			return
		}

		if res.ContentLength > 0 {
			t.Error("bad content length")
			return
		}

		if res.Header.Get("Content-Type") != "text/plain" {
			t.Error("bad content type")
			return
		}
	})

	t.Run("zero code", func(t *testing.T) {
		w := httptest.NewRecorder()
		b := "body"
		writeResponse(w, r, b, 0)

		res := w.Result()
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Error("bad status code")
			return
		}

		if res.ContentLength != int64(len(b)) {
			t.Error("bad content length")
			return
		}

		if res.Header.Get("Content-Type") != "text/plain" {
			t.Error("bad content type")
			return
		}
	})

	t.Run("explicit content type", func(t *testing.T) {
		w := httptest.NewRecorder()
		w.Header().Set("Content-Type", "application/json")
		b := "body"
		writeResponse(w, r, b, 0)

		res := w.Result()
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Error("bad status code")
			return
		}

		if res.ContentLength != int64(len(b)) {
			t.Error("bad content length")
			return
		}

		if res.Header.Get("Content-Type") != "application/json" {
			t.Error("bad content type")
			return
		}
	})
}

func TestHomeHandler(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	homeHandler(w, r)

	res := w.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Error("bad status code")
		return
	}

	if res.ContentLength < 1 {
		t.Error("bad content length")
		return
	}

	if res.Header.Get("Content-Type") != "text/html" {
		t.Error("bad content type")
		return
	}
}

func TestGetProfileConfig(t *testing.T) {
	t.Run("empty reader", func(t *testing.T) {
		// returns default profile
		c, err := getProfileConfig(strings.NewReader(""))
		if err != nil {
			t.Error(err)
			return
		}

		if len(c.RoleArn) > 0 {
			t.Error("received a role profile")
			return
		}
	})

	t.Run("nil reader", func(t *testing.T) {
		_, err := getProfileConfig(nil)
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("bad profile", func(t *testing.T) {
		// returns default profile
		c, err := getProfileConfig(strings.NewReader("bad-profile"))
		if err != nil {
			t.Error(err)
			return
		}

		if len(c.RoleArn) > 0 {
			t.Error("received a role profile")
			return
		}
	})

	t.Run("good", func(t *testing.T) {
		c, err := getProfileConfig(strings.NewReader("circle-role"))
		if err != nil {
			t.Error(err)
			return
		}

		if len(c.RoleArn) < 1 {
			t.Error("did not receive a role profile")
			return
		}

		if c.SourceProfile != "circleci" {
			t.Error("unexpected source profile")
			return
		}
	})
}

func TestSendProfile(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/profile", nil)
	w := httptest.NewRecorder()
	sendProfile(w, r)

	res := w.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Error("bad status code")
		return
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
		return
	}

	if string(b) != profile {
		t.Error("unexpected profile")
		return
	}
}

func TestGetMfa(t *testing.T) {
	t.Run("nil reader", func(t *testing.T) {
		_, err := getMfa(nil)
		if err == nil {
			t.Error("did not receive expected error")
			return
		}

		if err.code != http.StatusInternalServerError {
			t.Error("bad response code")
			return
		}
	})

	t.Run("empty reader", func(t *testing.T) {
		_, err := getMfa(strings.NewReader(""))
		if err == nil {
			t.Error("did not receive expected error")
			return
		}

		if err.code != http.StatusUnauthorized {
			t.Error("bad response code")
			return
		}
	})

	t.Run("short mfa", func(t *testing.T) {
		_, err := getMfa(strings.NewReader("123"))
		if err == nil {
			t.Error("did not receive expected error")
			return
		}

		if err.code != http.StatusUnauthorized {
			t.Error("bad response code")
			return
		}
	})

	t.Run("long mfa", func(t *testing.T) {
		c, err := getMfa(strings.NewReader("1234567890"))
		if err != nil {
			t.Error(err)
			return
		}

		if len(c) != 6 {
			t.Error("bad mfa code returned")
			return
		}

		if c != "123456" {
			t.Error("unexpected mfa code returned")
			return
		}
	})

	t.Run("good", func(t *testing.T) {
		c, err := getMfa(strings.NewReader("654321"))
		if err != nil {
			t.Error(err)
			return
		}

		if len(c) != 6 {
			t.Error("bad mfa code returned")
			return
		}

		if c != "654321" {
			t.Error("unexpected mfa code returned")
			return
		}
	})
}

func TestCredHandler(t *testing.T) {
	// can only test the bare-path request, otherwise we're calling out to AWS
	r := httptest.NewRequest(http.MethodGet, EC2MetadataCredentialPath, nil)
	w := httptest.NewRecorder()
	credHandler(w, r)

	res := w.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Error("bad response code")
		return
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
		return
	}

	if string(b) != profile {
		t.Error("unexpected profile name")
		return
	}
}

func TestRefreshHandler(t *testing.T) {
	cred = credentials.NewCredentials(new(mockProvider))

	t.Run("nil role", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, RefreshPath, nil)
		w := httptest.NewRecorder()
		refreshHandler(w, r)

		res := w.Result()
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Error("bad response code")
			return
		}
	})

	t.Run("with role", func(t *testing.T) {
		role = &cfglib.AwsConfig{AwsConfig: &config.AwsConfig{SourceProfile: "some-profile"}}
		cacheDir = os.TempDir()
		defer func() {
			role = nil
			cacheDir = ""
		}()

		r := httptest.NewRequest(http.MethodPost, RefreshPath, nil)
		w := httptest.NewRecorder()
		refreshHandler(w, r)

		res := w.Result()
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Error("bad response code")
			return
		}
	})
}

func TestListRolesHandler(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, ListRolesPath, nil)
	w := httptest.NewRecorder()
	listRoleHandler(w, r)

	res := w.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Error("bad response code")
		return
	}

	if res.ContentLength < 1 {
		t.Errorf("invalid content returned")
		return
	}

	if res.Header.Get("Content-Type") != "application/json" {
		t.Errorf("bad content type")
		return
	}
}

func TestCacheFile(t *testing.T) {
	cacheDir = os.TempDir()
	t.Run("empty profile", func(t *testing.T) {
		p := cacheFile("")
		if len(p) > 0 {
			t.Errorf("unexpected cache file name")
			return
		}
	})

	t.Run("good", func(t *testing.T) {
		p := cacheFile("test")
		if len(p) < 1 {
			t.Errorf("bad cache file name")
			return
		}

		if !strings.HasSuffix(p, "_test") {
			t.Errorf("bad cache file name")
			return
		}
	})

	t.Run("empty cache dir", func(t *testing.T) {
		cacheDir = ""
		p := cacheFile("test")
		if len(p) > 0 {
			t.Errorf("unexpected cache file name")
			return
		}
	})
}

func TestHandleOptions(t *testing.T) {
	err := handleOptions(new(EC2MetadataInput))
	if err != nil {
		t.Error(err)
		return
	}

	t.Run("nil logger", func(t *testing.T) {
		if log == nil {
			t.Error("configured a nil logger")
		}
	})

	t.Run("empty cache", func(t *testing.T) {
		if len(cacheDir) < 1 {
			t.Error("empty cache dir")
		}
	})

	t.Run("nil config resolver", func(t *testing.T) {
		if cfg == nil {
			t.Error("nil config resolver")
		}
	})
}

func TestCheckSudoEnv(t *testing.T) {
	t.Run("env vars set", func(t *testing.T) {
		os.Setenv("SUDO_UID", "9999")
		os.Setenv("SUDO_GID", "9998")
		defer func() {
			os.Unsetenv("SUDO_UID")
			os.Unsetenv("SUDO_GID")
		}()

		uid, gid, err := checkSudoEnv()
		if err != nil {
			t.Error(err)
		}

		if uid != 9999 || gid != 9998 {
			t.Errorf("Bad UID/GID value, got UID: %d, GID: %d", uid, gid)
		}
	})

	t.Run("env vars unset", func(t *testing.T) {
		os.Unsetenv("SUDO_UID")
		os.Unsetenv("SUDO_GID")

		_, _, err := checkSudoEnv()
		if err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestCheckCacheDir(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Run("valid cache dir", func(t *testing.T) {
			if _, _, err := stat(os.TempDir()); err != nil {
				t.Error(err)
			}
		})

		t.Run("invalid cache dir", func(t *testing.T) {
			if _, _, err := stat(""); err == nil {
				t.Error("did not receive expected error")
			}
		})
	} else {
		t.Skip("skipping test on Windows")
	}
}

func TestCheckHomeDir(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Run("valid home dir", func(t *testing.T) {
			if _, _, err := statHomeDir(); err != nil {
				t.Error(err)
			}
		})

		t.Run("invalid home dir", func(t *testing.T) {
			curHome, err := os.UserHomeDir()
			if err != nil {
				t.Error(err)
			}

			os.Unsetenv("HOME")
			defer os.Setenv("HOME", curHome)

			if _, _, err := statHomeDir(); err == nil {
				t.Error("did not receive expected error")
			}
		})
	} else {
		t.Skip("skipping test on Windows")
	}
}

func TestSetPrivileges(t *testing.T) {
	t.Run("self", func(t *testing.T) {
		if _, ok := os.LookupEnv("CIRCLECI"); ok {
			t.Skip("skipping test in circleci environment")
		} else {
			if err := setPrivileges(os.Getuid(), os.Getgid()); err != nil {
				t.Error(err)
			}
		}
	})

	t.Run("other", func(t *testing.T) {
		if os.Getuid() != 0 {
			if err := setPrivileges(1, 1); err == nil {
				t.Error("did not receive expected error")
			}
		} else {
			t.Skip("skipping test because we're UID 0")
		}
	})

	t.Run("other uid", func(t *testing.T) {
		if os.Getuid() != 0 {
			if err := setPrivileges(1, os.Getgid()); err == nil {
				t.Error("did not receive expected error")
			}
		} else {
			t.Skip("skipping test because we're UID 0")
		}
	})
}

type mockProvider string

func (p *mockProvider) IsExpired() bool {
	return true
}

func (p *mockProvider) Retrieve() (credentials.Value, error) {
	return credentials.Value{}, nil
}
