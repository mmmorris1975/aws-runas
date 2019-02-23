package metadata_services

import (
	"context"
	"github.com/mmmorris1975/aws-config/config"
	cfglib "github.com/mmmorris1975/aws-runas/lib/config"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestProfileListHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, EC2MetadataCredentialPath, nil)

	t.Run("no context", func(t *testing.T) {
		w := httptest.NewRecorder()
		profileListHandler(w, req)
		res := w.Result()
		defer res.Body.Close()

		if res.StatusCode != http.StatusBadRequest {
			t.Error("unexpected http status code")
		}
	})

	t.Run("with context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ctxKeyProfile, "my-test")
		w := httptest.NewRecorder()
		profileListHandler(w, req.WithContext(ctx))
		res := w.Result()
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Error("unexpected http failure")
			return
		}

		b, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Errorf("error reading response body: %v", err)
			return
		}

		if string(b) != "my-test" {
			t.Error("bad response body content")
		}
	})
}

func TestListRoleHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, ListRolePath, nil)

	os.Setenv(config.ConfigFileEnvVar, "../../.aws/config")
	defer os.Unsetenv(config.ConfigFileEnvVar)

	c, err := cfglib.NewConfigResolver(nil)
	if err != nil {
		t.Error(err)
		return
	}
	cfg = c

	t.Run("good", func(t *testing.T) {
		w := httptest.NewRecorder()
		listRoleHandler(w, req)
		res := w.Result()
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Error("bad http response code")
			return
		}

		b, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Errorf("error reading response body: %v", err)
			return
		}

		if string(b) != `["circle-role"]` {
			t.Error("bad response body content")
			return
		}
	})
}
