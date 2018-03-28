package lib

import (
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"os"
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

func AwsConfigFile() string {
	c := defaults.SharedConfigFilename()
	e, ok := os.LookupEnv("AWS_CONFIG_FILE")
	if ok && len(e) > 0 {
		c = e
	}
	return c
}