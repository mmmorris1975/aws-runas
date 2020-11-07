package metadata

import (
	"net"
	"testing"
)

func Test_DiscoverLoopback(t *testing.T) {
	if _, err := discoverLoopback(); err != nil {
		t.Error(err)
		return
	}
}

func Test_findInterfaceByAddress(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		i, err := findInterfaceByAddress(net.IPv6loopback.String())
		if err != nil {
			// try IPv4 loopback before failing, since the IPv6 address fails in CI
			// never understood why this isn't a language constant like IPv6 loopback
			i, err = findInterfaceByAddress("127.0.0.1")
			if err != nil {
				t.Error(err)
				return
			}
		}

		if i == nil {
			t.Errorf("nil interface")
		}
	})

	t.Run("bad", func(t *testing.T) {
		if _, err := findInterfaceByAddress(net.IPv4allrouter.String()); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func Test_doCommand(t *testing.T) {
	if err := doCommand([]string{"true"}); err != nil {
		t.Error(err)
	}
}
