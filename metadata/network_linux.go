// +build linux

package metadata

import "net"

func addAddress(iface *net.Interface, cidrAddr string) error {
	cmd := []string{"ip", "address", "add", cidrAddr, "dev", iface.Name}
	return doCommand(cmd)
}

func removeAddress() error {
	mu.Lock()
	defer mu.Unlock()
	iface, err := findInterfaceByAddress(DefaultEc2ImdsAddr)
	if err != nil {
		return err
	}

	cmd := []string{"ip", "address", "del", DefaultEc2ImdsCidr, "dev", iface.Name}
	return doCommand(cmd)
}
