// +build darwin freebsd netbsd openbsd

package metadata

import "net"

func addAddress(iface *net.Interface, cidrAddr string) error {
	cmd := []string{"ifconfig", iface.Name, "alias", cidrAddr}
	return doCommand(cmd)
}

func removeAddress() error {
	mu.Lock()
	defer mu.Unlock()
	iface, err := findInterfaceByAddress(DefaultEc2ImdsAddr)
	if err != nil {
		return err
	}

	cmd := []string{"ifconfig", iface.Name, "-alias", DefaultEc2ImdsAddr}
	return doCommand(cmd)
}
