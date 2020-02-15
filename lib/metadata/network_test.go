package metadata

import "testing"

func TestDiscoverLoopback(t *testing.T) {
	t.Run("Loopback", func(t *testing.T) {
		_, err := discoverLoopback()
		if err != nil {
			t.Errorf("Unexpected error getting loopback interface: %v", err)
		}
	})
}

func TestDoCommand(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		if err := doCommand([]string{"true"}); err != nil {
			t.Error(err)
		}
	})

	t.Run("bad", func(t *testing.T) {
		if err := doCommand([]string{"not-a-commadn"}); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

// These require admin/sudo privileges, so these won't work in automation
//func TestEndpoint(t *testing.T) {
//	lo, err := discoverLoopback()
//	if err != nil {
//		t.Errorf("Unexpected error getting loopback interface: %v", err)
//	}
//
//	t.Run("ConfigureAddress", func(t *testing.T) {
//		if err := addAddress(lo, ec2MetadataAddress); err != nil {
//			t.Errorf("Unexpected error configuring metadata service address: %v", err)
//		}
//	})
//	t.Run("RemoveAddress", func(t *testing.T) {
//		if err := removeAddress(lo, ec2MetadataAddress); err != nil {
//			t.Errorf("Unexpected error removing metadata service address: %v", err)
//		}
//	})
//}
