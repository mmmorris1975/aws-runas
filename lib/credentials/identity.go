package credentials

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"strings"
)

// AwsIdentity holds the identity information for a set of AWS credentials gathered via the sts.GetCallerIdentity API call
type AwsIdentity struct {
	Identity     *sts.GetCallerIdentityOutput
	IdentityType string
	UserName     string
}

// AwsIdentityManager provides the facility to fetch AwsIdentity information for the caller
type AwsIdentityManager struct {
	client stsiface.STSAPI
	cfg    *aws.Config
	log    aws.Logger
}

// NewAwsIdentityManager creates a new AWS Identity Manager using the given ConfigProvider/Session
func NewAwsIdentityManager(c client.ConfigProvider) *AwsIdentityManager {
	m := AwsIdentityManager{client: sts.New(c), cfg: c.ClientConfig("sts").Config}
	return &m
}

// WithLogger configures a conforming Logger
func (m *AwsIdentityManager) WithLogger(l aws.Logger) *AwsIdentityManager {
	m.log = l
	return m
}

// GetCallerIdentity calls the STS GetCallerIdentity function to retrieve the AWS identity
// information associated with the caller's credentials.
func (m *AwsIdentityManager) GetCallerIdentity() (*AwsIdentity, error) {
	o, err := m.client.GetCallerIdentity(new(sts.GetCallerIdentityInput))
	if err != nil {
		m.debug("error calling GetCallerIdentity(): %v", err)
		return nil, err
	}

	a, err := arn.Parse(*o.Arn)
	if err != nil {
		m.debug("error parsing identity ARN: %v", err)
		return nil, err
	}

	id := AwsIdentity{Identity: o}

	r := strings.Split(a.Resource, "/")
	id.IdentityType = r[0]
	id.UserName = r[len(r)-1]

	return &id, nil
}

func (m *AwsIdentityManager) debug(f string, v ...interface{}) {
	if m.cfg != nil && m.cfg.LogLevel.AtLeast(aws.LogDebug) && m.log != nil {
		m.log.Log(fmt.Sprintf(f, v...))
	}
}
