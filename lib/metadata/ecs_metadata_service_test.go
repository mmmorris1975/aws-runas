package metadata

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewEcsMetadataService(t *testing.T) {
	t.Run("nil opts", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewEcsMetadataService with nil config")
			}
		}()
		NewEcsMetadataService(nil)
	})

	t.Run("empty opts", func(t *testing.T) {
		ecs, err := NewEcsMetadataService(new(EcsMetadataInput))
		if err != nil {
			t.Error(err)
			return
		}

		if ecs.Url.Scheme != "http" {
			t.Errorf("unexpected url scheme: %s", ecs.Url.Scheme)
		}
	})
}

func TestEcsHandler(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		cred = credentials.NewStaticCredentials("MockAK", "MockSK", "MockToken")

		r := httptest.NewRequest(http.MethodGet, EcsCredentialsPath, nil)
		w := httptest.NewRecorder()

		ecsHandler(w, r)

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

		c := new(ecsCredentials)
		if err := json.Unmarshal(b, c); err != nil {
			t.Error(err)
		}

		if c.AccessKeyId != "MockAK" || c.SecretAccessKey != "MockSK" || c.Token != "MockToken" {
			t.Error("unexpected response credentials")
		}
	})

	t.Run("bad", func(t *testing.T) {
		p := credentials.ErrorProvider{Err: fmt.Errorf("bad times"), ProviderName: "Error Provider"}
		cred = credentials.NewCredentials(&p)

		r := httptest.NewRequest(http.MethodGet, EcsCredentialsPath, nil)
		w := httptest.NewRecorder()

		ecsHandler(w, r)

		res := w.Result()
		defer res.Body.Close()

		if res.StatusCode == http.StatusOK {
			t.Error("bad response code")
			return
		}

		b, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Error(err)
			return
		}

		c := new(ecsCredentialError)
		if err := json.Unmarshal(b, c); err != nil {
			t.Error(err)
		}

		if c.Message != p.Err.Error() {
			t.Error("mismatched error text")
		}
	})
}
