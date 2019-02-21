package main

import "testing"

func TestVersionCheck(t *testing.T) {
	if err := versionCheck(""); err != nil {
		t.Errorf("Unexpected error from VersionCheck: %v", err)
	}
}
