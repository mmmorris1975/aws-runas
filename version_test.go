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
		w.Header().Set("Location", "https://example.org/aws-runas/releases/0.0.0/")
		w.WriteHeader(http.StatusFound)
	}))
	defer s.Close()

	ghUrl = s.URL

	if err := versionCheck(""); err != nil {
		t.Errorf("Unexpected error from VersionCheck: %v", err)
	}
}

func ExampleVersionCheck() {
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
