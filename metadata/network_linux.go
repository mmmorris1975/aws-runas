// +build linux

package metadata

import "net"

func addAddress(iface *net.Interface, cidrAddr string) error {
	cmd := []string{"ip", "address", "add", cidrAddr, "dev", iface.Name}
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

	cmd := []string{"ip", "address", "del", cidrAddr, "dev", iface.Name}
	return doCommand(cmd)
}
