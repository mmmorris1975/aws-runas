package metadata

import "net"

// ECSMetadataIp is the IP address of the ECS task metadata service
const ECSMetadataIp = "169.254.170.2"

// ECSMetadataAddress is the net.IPAddr of the ECS task metadata service
var ECSMetadataAddress *net.IPAddr

func init() {
	ECSMetadataAddress, _ = net.ResolveIPAddr("ip", ECSMetadataIp)
}

// NewECSMetadataService, once implemented, will provide an HTTP interface similar to the ECS task credential provider
// endpoint in AWS
func NewECSMetadataService() error {
	// todo noop
	return nil
}
