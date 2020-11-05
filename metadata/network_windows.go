// +build windows

package metadata

import "net"

func addAddress(iface *net.Interface, cidrAddr string) error {
	ip, mask, err := net.ParseCIDR(cidrAddr)
	if err != nil {
		return err
	}

	cmd := []string{"netsh", "interface", "ipv4", "add", "address", iface.Name, ip.String(), mask.To4().String()}
	return doCommand(cmd)
}

func removeAddress(cidrAddr string) error {
	ip, _, err := net.ParseCIDR(cidrAddr)
	if err != nil {
		return err
	}

	var iface *net.Interface
	iface, err = findInterfaceByAddress(ip.String())
	if err != nil {
		return err
	}

	cmd := []string{"netsh", "interface", "ipv4", "delete", "address", iface.Name, ip.String()}
	return doCommand(cmd)
}
