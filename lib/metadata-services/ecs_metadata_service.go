package metadata_services

import "net"

// ECSMetadataIp is the IP address of the ECS task metadata service
const ECSMetadataIp = "169.254.170.2"

// ECSMetadataAddress is the net.IPAddr of the ECS task metadata service
var ECSMetadataAddress *net.IPAddr

func init() {
	ECSMetadataAddress, _ = net.ResolveIPAddr("ip", ECSMetadataIp)
}

func NewECSMetadataService() error {
	// todo noop
	return nil
}
