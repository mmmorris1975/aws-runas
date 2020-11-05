package metadata

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// Loop through the system's available network interfaces and return the name of the 1st one which is up and a loopback
// interface.  Return an error if the call to net.Interfaces() fails, or no suitable network interface is found.
func discoverLoopback() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range ifaces {
		if (i.Flags&net.FlagUp == net.FlagUp) && (i.Flags&net.FlagLoopback == net.FlagLoopback) {
			return &i, nil
		}
	}

	return nil, fmt.Errorf("no suitable loopback interface found")
}

func findInterfaceByAddress(addr string) (*net.Interface, error) {
	ifaceList, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var addrs []net.Addr
	for _, i := range ifaceList {
		addrs, err = i.Addrs()
		if err != nil {
			// non-fatal, just move on
			continue
		}

		for _, a := range addrs {
			if strings.HasPrefix(a.String(), addr) {
				return &i, nil
			}
		}
	}
	return nil, errors.New("no interface found for address")
}

func doCommand(cmd []string) error {
	c := exec.Command(cmd[0], cmd[1:]...) //nolint:gosec
	c.Stdin = nil
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	return c.Run()
}
