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

// These require admin/sudo privileges, so these won't work in automation
//func TestEndpoint(t *testing.T) {
//	lo, err := discoverLoopback()
//	if err != nil {
//		t.Errorf("Unexpected error getting loopback interface: %v", err)
//	}
//
//	t.Run("ConfigureAddress", func(t *testing.T) {
//		if err := addAddress(lo, EC2MetadataAddress); err != nil {
//			t.Errorf("Unexpected error configuring metadata service address: %v", err)
//		}
//	})
//	t.Run("RemoveAddress", func(t *testing.T) {
//		if err := removeAddress(lo, EC2MetadataAddress); err != nil {
//			t.Errorf("Unexpected error removing metadata service address: %v", err)
//		}
//	})
//}
