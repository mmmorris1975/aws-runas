package metadata

import (
	"os"
	"testing"
)

func Test_checkSudoEnv(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		os.Setenv("SUDO_UID", "1111")
		os.Setenv("SUDO_GID", "1111")

		defer func() {
			os.Unsetenv("SUDO_UID")
			os.Unsetenv("SUDO_GID")
		}()

		if _, _, err := checkSudoEnv(); err != nil {
			t.Error(err)
		}
	})

	t.Run("partial", func(t *testing.T) {
		os.Setenv("SUDO_GID", "1111")

		defer func() {
			os.Unsetenv("SUDO_GID")
		}()

		if _, _, err := checkSudoEnv(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("not set", func(t *testing.T) {
		os.Unsetenv("SUDO_UID")
		os.Unsetenv("SUDO_GID")

		if _, _, err := checkSudoEnv(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("bad data", func(t *testing.T) {
		os.Setenv("SUDO_UID", "1111")
		os.Setenv("SUDO_GID", "this should never happen, but let's make sure Atoi() fails")

		defer func() {
			os.Unsetenv("SUDO_UID")
			os.Unsetenv("SUDO_GID")
		}()

		if _, _, err := checkSudoEnv(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func Test_statHomeDir(t *testing.T) {
	if _, _, err := statHomeDir(); err != nil {
		t.Error(err)
	}
}

func Test_stat(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		if _, _, err := stat(t.TempDir()); err != nil {
			t.Error(err)
		}
	})

	t.Run("bad", func(t *testing.T) {
		if _, _, err := stat("does not exist"); err == nil {
			t.Error("stat'd an invalid path")
		}
	})

	t.Run("empty", func(t *testing.T) {
		if _, _, err := stat(""); err == nil {
			t.Error("stat'd an empty path")
		}
	})
}
