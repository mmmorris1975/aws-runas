package util

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/mmmorris1975/aws-runas/lib/config"
	"net/http"
	"os"
	"strings"
)

// LookupMfa retrieves the MFA devices configured for the calling user's IAM account
func LookupMfa(c client.ConfigProvider) ([]*iam.MFADevice, error) {
	s := iam.New(c)

	res, err := s.ListMFADevices(&iam.ListMFADevicesInput{})
	if err != nil {
		return nil, err
	}

	return res.MFADevices, nil
}

// VersionCheck will check the program version against the latest release according to github
func VersionCheck(version string) error {
	u := "https://github.com/mmmorris1975/aws-runas/releases/latest"
	r, err := http.NewRequest(http.MethodHead, u, http.NoBody)
	if err != nil {
		return err
	}

	// Get in the weeds so we don't follow redirects
	res, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusFound {
		url, err := res.Location()
		if err != nil {
			return err
		}

		p := strings.Trim(url.Path, `/`)
		f := strings.Split(p, `/`)
		v := f[len(f)-1]

		if v != version {
			fmt.Printf("New version of aws-runas available: %s\nDownload available at: %s\n", v, u)
		}
		return nil
	}

	return fmt.Errorf("version check failed, bad HTTP Status: %d", res.StatusCode)
}

// RunDiagnostics will sanity check various configuration items
func RunDiagnostics(c *config.AwsConfig) error {
	envAk := os.Getenv("AWS_ACCESS_KEY_ID")
	envSt := os.Getenv("AWS_SESSION_TOKEN")

	if len(envAk) > 0 && len(envSt) > 0 {
		if strings.HasPrefix(envAk, "AKIA") {
			return fmt.Errorf("detected static access key env var along with session token env var, this is invalid")
		}
	}

	//fmt.Printf("PROFILE: %s\n", p.Name)
	fmt.Printf("ROLE ARN: %s\n", c.RoleArn)
	fmt.Printf("MFA SERIAL: %s\n", c.MfaSerial)
	fmt.Printf("EXTERNAL ID: %s\n", c.ExternalID)
	//fmt.Printf("ROLE SESSION NAME: %s\n", c.RoleSessionName)
	fmt.Printf("SESSION TOKEN DURATION: %s\n", c.SessionDuration)
	fmt.Printf("ASSUME ROLE CREDENTIAL DURATION: %s\n", c.RoleDuration)
	fmt.Printf("REGION: %s\n", c.Region)
	fmt.Printf("SOURCE PROFILE: %s\n", c.SourceProfile)

	// fixme
	//c := AwsCredentialsFile()
	//f, err := ini.Load(c)
	//if err != nil {
	//	return err
	//}
	//f.BlockMode = false
	//
	//profile := c.SourceProfile
	//if len(profile) < 1 {
	//	profile = p.Name
	//}
	//
	//s, err := f.GetSection(profile)
	//if err != nil {
	//	// if access key envvar exists, assume creds are configured as envvars and not in credentials file
	//	// otherwise, flag as an error, since creds are totally missing
	//	if len(envAk) < 1 {
	//		return fmt.Errorf("missing [%s] section in credentials file %s", profile, c)
	//	}
	//
	//}
	//
	//if s.HasKey("aws_access_key_id") && s.HasKey("aws_secret_access_key") {
	//	if len(envAk) > 0 || len(envSt) > 0 {
	//		return fmt.Errorf("detected AWS credential environment variables and profile credentials, this may confuse aws-runas")
	//	}
	//} else {
	//	// section is in cred file, but one or both of the cred keys are missing
	//	if len(envAk) < 1 {
	//		return fmt.Errorf("profile found in credentials file, but missing credential configuration")
	//	}
	//}

	return nil
}
