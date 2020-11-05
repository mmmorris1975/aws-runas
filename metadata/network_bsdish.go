// +build darwin freebsd netbsd openbsd

package metadata

import "net"

func addAddress(iface *net.Interface, cidrAddr string) error {
	cmd := []string{"ifconfig", iface.Name, "alias", cidrAddr}
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

	cmd := []string{"ifconfig", iface.Name, "-alias", ip.String()}
	return doCommand(cmd)
}
