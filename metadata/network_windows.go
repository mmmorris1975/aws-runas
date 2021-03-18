// +build windows

package metadata

import (
	"net"
)

func addAddress(iface *net.Interface, cidrAddr string) error {
	ip, subnet, err := net.ParseCIDR(cidrAddr)
	if err != nil {
		return err
	}

	cmd := []string{"netsh", "interface", "ipv4", "add", "address", iface.Name, ip.String(), net.IP(subnet.Mask).String()}
	return doCommand(cmd)
}

func removeAddress() error {
	mu.Lock()
	defer mu.Unlock()
	iface, err := findInterfaceByAddress(DefaultEc2ImdsAddr)
	if err != nil {
		return err
	}

	cmd := []string{"netsh", "interface", "ipv4", "delete", "address", iface.Name, DefaultEc2ImdsAddr}
	return doCommand(cmd)
}
