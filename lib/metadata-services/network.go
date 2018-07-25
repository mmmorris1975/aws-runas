package metadata_services

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
)

var (
	EC2MetadataAddress *net.IPAddr
	ECSMetadataAddress *net.IPAddr
)

func init() {
	EC2MetadataAddress, _ = net.ResolveIPAddr("ip", "169.254.169.254")
	ECSMetadataAddress, _ = net.ResolveIPAddr("ip", "169.254.170.2")
}

// Loop through the system's available network interfaces and return the name of the 1st one which is up and a loopback
// interface.  Return an error if the call to net.Interfaces() fails, or no suitable network interface is found.
func discoverLoopback() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, i := range ifaces {
		if (i.Flags&net.FlagUp == net.FlagUp) && (i.Flags&net.FlagLoopback == net.FlagLoopback) {
			return i.Name, nil
		}
	}

	return "", fmt.Errorf("no suitable loopback interface found")
}

func addAddress(iface string, addr *net.IPAddr) error {
	var cmd []string

	switch runtime.GOOS {
	case "linux":
		cmd = []string{"ip", "address", "add", addr.String() + "/22", "dev", iface}
	case "darwin":
		cmd = []string{"ifconfig", iface, "alias", addr.String() + "/22"}
	case "windows":
		cmd = []string{"netsh", "interface", "ipv4", "add", "address", iface, addr.String(), "255.255.252.0"}
	default:
		return fmt.Errorf("unsupported platform (%s) for metadata service configuration", runtime.GOOS)
	}

	return doCommand(cmd)
}

func removeAddress(iface string, addr *net.IPAddr) error {
	var cmd []string

	switch runtime.GOOS {
	case "linux":
		cmd = []string{"ip", "address", "del", addr.String() + "/22", "dev", iface}
	case "darwin":
		cmd = []string{"ifconfig", iface, "-alias", addr.String()}
	case "windows":
		cmd = []string{"netsh", "interface", "ipv4", "delete", "address", iface, addr.String()}
	default:
		return fmt.Errorf("unsupported platform (%s) for metadata service configuration", runtime.GOOS)
	}

	return doCommand(cmd)
}

func doCommand(cmd []string) error {
	c := exec.Command(cmd[0], cmd[1:]...)
	c.Stdin = nil
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	return c.Run()
}
