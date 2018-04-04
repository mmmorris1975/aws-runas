package lib

import (
	"os"
	"testing"
)

func TestNewCredentialsCacher(t *testing.T) {
	t.Run("FileNil", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewCredentialCacher with nil profile")
			}
		}()
		NewCredentialsCacher("", new(CredentialsCacherOptions))
	})

	t.Run("OptionsNil", func(t *testing.T) {
		p := NewCredentialsCacher(os.Stdout.Name(), nil)
		if p.CacheFile() != os.Stdout.Name() {
			t.Errorf("Unexpected value returned when passing nil options")
		}
	})
}

func TestCredentialsCacher_Fetch(t *testing.T) {
	p := NewCredentialsCacher(os.DevNull, new(CredentialsCacherOptions))

	t.Run("EmptyCreds", func(t *testing.T) {
		if c, err := p.Fetch(); err == nil {
			t.Errorf("Got credentials when none expected: %+v", c)
		}
	})
}

func TestCredentialsCacher_Store(t *testing.T) {
	p := NewCredentialsCacher(os.DevNull, new(CredentialsCacherOptions))

	t.Run("CredsNil", func(t *testing.T) {
		if err := p.Store(nil); err == nil {
			t.Errorf("Did not get expected error attempting to store nil credentials")
		}
	})

	t.Run("CredsDefaults", func(t *testing.T) {
		if err := p.Store(new(CachableCredentials)); err != nil {
			t.Errorf("Got unexpected error attempting to store nil credentials: %v", err)
		}
	})
}
