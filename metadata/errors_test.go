package metadata

import "testing"

func TestWebAuthenticationError_Error(t *testing.T) {
	var e WebAuthenticationError
	e = "test"

	if e.Error() != string(e) {
		t.Error("data mismatch")
	}
}

func TestNewWebAuthenticationError(t *testing.T) {
	e := NewWebAuthenticationError()
	if e.Error() != "AUTH" {
		t.Error("data mismatch")
	}
}

func TestNewWebMfaRequiredError(t *testing.T) {
	e := NewWebMfaRequiredError()
	if e.Error() != "MFA" {
		t.Error("data mismatch")
	}
}
