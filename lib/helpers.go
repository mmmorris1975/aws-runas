package lib

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/go-ini/ini"
	"net/http"
	"os"
	"strings"
)

// IAM_ARN is the prefix for role ARNs and Virtual MFA devices
// (physical MFA devices use device serial number, not ARN)
const IAM_ARN = "arn:aws:iam::"

// LookupMfa retrieves the MFA devices configured for the calling user's IAM account
func LookupMfa(sess *session.Session) ([]*iam.MFADevice, error) {
	s := iam.New(sess)

	res, err := s.ListMFADevices(&iam.ListMFADevicesInput{})
	if err != nil {
		return nil, err
	}

	return res.MFADevices, nil
}

// PromptForMfa will print a prompt to Stdout for a user to enter the MFA code
func PromptForMfa() string {
	var mfaCode string
	fmt.Print("Enter MFA Code: ")
	fmt.Scanln(&mfaCode)
	return mfaCode
}

// AwsConfigFile returns the location of the AWS SDK config file.  Use the
// value of the AWS_CONFIG_FILE environment variable, if available, otherwise
// use the SDK default location
func AwsConfigFile() string {
	c := defaults.SharedConfigFilename()
	e, ok := os.LookupEnv("AWS_CONFIG_FILE")
	if ok && len(e) > 0 {
		c = e
	}
	return c
}

func AwsCredentialsFile() string {
	c := defaults.SharedCredentialsFilename()
	e, ok := os.LookupEnv("AWS_SHARED_CREDENTIALS_FILE")
	if ok && len(e) > 0 {
		c = e
	}
	return c
}

// AwsSession returns an AWS SDK session object to use for making API calls to AWS.  This session
// will be set to get configuration from the shared configuration files, and enable verbose credential
// chain logging. If the profile argument is provided, the session will be set to use it for configuration.
func AwsSession(profile string) *session.Session {
	// Doing this kills the ability to use env vars, which may mess
	// with the -M option, requiring the ~/.aws/credentials file
	// Unset AWS credential env vars
	//env := []string{
	//	"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY",
	//	"AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY",
	//	"AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
	//}
	//for _, e := range env {
	//	os.Unsetenv(e)
	//}

	opts := session.Options{
		SharedConfigState:       session.SharedConfigEnable,
		AssumeRoleTokenProvider: stscreds.StdinTokenProvider,
		Config:                  aws.Config{CredentialsChainVerboseErrors: aws.Bool(true)},
	}

	if len(profile) > 0 {
		opts.Profile = profile
	}

	return session.Must(session.NewSessionWithOptions(opts))
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
func RunDiagnostics(p *AWSProfile) error {
	envAk := os.Getenv("AWS_ACCESS_KEY_ID")
	envSt := os.Getenv("AWS_SESSION_TOKEN")

	if len(envAk) > 0 && len(envSt) > 0 {
		if strings.HasPrefix(envAk, "AKIA") {
			return fmt.Errorf("detected static access key env var along with session token env var, this is invalid")
		}
	}

	fmt.Printf("PROFILE: %s\n", p.Name)
	fmt.Printf("ROLE ARN: %s\n", p.RoleArn)
	fmt.Printf("MFA SERIAL: %s\n", p.MfaSerial)
	fmt.Printf("EXTERNAL ID: %s\n", p.ExternalId)
	fmt.Printf("ROLE SESSION NAME: %s\n", p.RoleSessionName)
	fmt.Printf("SESSION TOKEN DURATION: %s\n", p.SessionDuration)
	fmt.Printf("ASSUME ROLE CREDENTIAL DURATION: %s\n", p.CredDuration)
	fmt.Printf("REGION: %s\n", p.Region)
	fmt.Printf("SOURCE PROFILE: %s\n", p.SourceProfile)

	c := AwsCredentialsFile()
	f, err := ini.Load(c)
	if err != nil {
		return err
	}
	f.BlockMode = false

	profile := p.SourceProfile
	if len(profile) < 1 {
		profile = p.Name
	}

	s, err := f.GetSection(profile)
	if err != nil {
		// if access key envvar exists, assume creds are configured as envvars and not in credentials file
		// otherwise, flag as an error, since creds are totally missing
		if len(envAk) < 1 {
			return fmt.Errorf("missing [%s] section in credentials file %s", profile, c)
		}

	}

	if s.HasKey("aws_access_key_id") && s.HasKey("aws_secret_access_key") {
		if len(envAk) > 0 || len(envSt) > 0 {
			return fmt.Errorf("detected AWS credential environment variables and profile credentials, this may confuse aws-runas")
		}
	} else {
		// section is in cred file, but one or both of the cred keys are missing
		if len(envAk) < 1 {
			return fmt.Errorf("profile found in credentials file, but missing credential configuration")
		}
	}

	return nil
}
