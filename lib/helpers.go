package lib

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

// Lookup the MFA devices configured for the calling user's IAM account
func LookupMfa(sess *session.Session) ([]*iam.MFADevice, error) {
	s := iam.New(sess)

	res, err := s.ListMFADevices(&iam.ListMFADevicesInput{})
	if err != nil {
		return nil, err
	}

	return res.MFADevices, nil
}