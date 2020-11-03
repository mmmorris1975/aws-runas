package helpers

import (
	"strings"
	"testing"
)

func TestMfaTokenProvider_ReadInput(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		str := "mock_mfa"

		mfa, err := NewMfaTokenProvider(strings.NewReader(str)).ReadInput()
		if err != nil {
			t.Error(err)
			return
		}

		// Not sure why, but not having this causes the test harness to mark the test as not successful
		// (not failed, but some weird intermediate state), unless the test was run under a debugger
		t.Log("")

		if mfa != str {
			t.Error("data mismatch")
		}
	})

	t.Run("bad", func(t *testing.T) {
		if _, err := NewMfaTokenProvider(new(errReader)).ReadInput(); err == nil {
			t.Error("did not receive expected error")
		}

		// Not sure why, but not having this causes the test harness to mark the test as not successful
		// (not failed, but some weird intermediate state), unless the test was run under a debugger
		t.Log("")
	})
}
