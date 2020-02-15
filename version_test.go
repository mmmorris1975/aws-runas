package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVersionCheck(t *testing.T) {
	if err := versionCheck(""); err != nil {
		t.Errorf("Unexpected error from VersionCheck: %v", err)
	}
}

func TestVersionCheck_Http(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad-code" {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		if r.URL.Path == "/bad-header" {
			http.Error(w, "redirect", http.StatusFound)
			return
		}

		w.Header().Set("Location", "https://example.org/aws-runas/releases/0.0.0/")
		w.WriteHeader(http.StatusFound)
	}))
	defer s.Close()

	t.Run("good", func(t *testing.T) {
		ghUrl = s.URL

		if err := versionCheck(""); err != nil {
			t.Errorf("Unexpected error from VersionCheck: %v", err)
		}
	})

	t.Run("bad code", func(t *testing.T) {
		ghUrl = s.URL + "/bad-code"

		if err := versionCheck(""); err == nil {
			t.Errorf("did not receive expected error")
		}
	})

	t.Run("bad header", func(t *testing.T) {
		ghUrl = s.URL + "/bad-header"

		if err := versionCheck(""); err == nil {
			t.Errorf("did not receive expected error")
		}
	})
}

func Example_versionCheck() {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.org/aws-runas/releases/0.0.0/")
		w.WriteHeader(http.StatusFound)
	}))
	defer s.Close()

	ghUrl = s.URL
	versionCheck("")
	// Output:
	// New version of aws-runas available: 0.0.0
	// Download available at: https://example.org/aws-runas/releases/0.0.0/
}
