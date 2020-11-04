package cli

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/urfave/cli/v2"
	"gopkg.in/ini.v1"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const diagDesc = `Check the configuration of the given 'profile_name' argument to see if there are
   any inconsistencies which may prevent the program from functioning properly.`

var diagCmd = &cli.Command{
	Name:        "diagnose",
	Aliases:     []string{"diag"},
	Usage:       diagFlag.Usage,
	ArgsUsage:   "[profile_name]",
	Description: diagDesc,

	Action: func(ctx *cli.Context) error {
		log.Debug("Diagnostics")
		_, cfg, err := resolveConfig(ctx, 1)
		if err != nil {
			return err
		}

		if len(cfg.ProfileName) < 1 {
			log.Warning("No profile specified, will only check default section. Provide a profile name for more validation")
			cfg.ProfileName = session.DefaultSharedConfigProfile
		}

		checkEnv()
		checkRegion(cfg.Region)
		checkProfileCfg(cfg)
		checkTime()

		printConfig(cfg)

		return nil
	},
}

func printConfig(cfg *config.AwsConfig) {
	fmt.Printf("PROFILE: %s\n", cfg.ProfileName)
	fmt.Printf("REGION: %s\n", cfg.Region)
	fmt.Printf("SOURCE PROFILE: %s\n", cfg.SrcProfile)
	fmt.Printf("SESSION TOKEN DURATION: %s\n", cfg.SessionTokenDuration)
	fmt.Printf("MFA SERIAL: %s\n", cfg.MfaSerial)
	fmt.Printf("ROLE ARN: %s\n", cfg.RoleArn)
	fmt.Printf("EXTERNAL ID: %s\n", cfg.ExternalId)
	fmt.Printf("ASSUME ROLE CREDENTIAL DURATION: %s\n", cfg.CredentialsDuration)

	if len(cfg.SamlUrl) > 0 {
		fmt.Printf("SAML ENDPOINT URL: %s\n", cfg.SamlUrl)
		fmt.Printf("SAML USERNAME: %s\n", cfg.SamlUsername)
		fmt.Printf("JUMP ROLE ARN: %s\n", cfg.JumpRoleArn)
	}

	if len(cfg.WebIdentityUrl) > 0 {
		fmt.Printf("WEB IDENTITY ENDPOINT URL: %s\n", cfg.WebIdentityUrl)
		fmt.Printf("WEB IDENTITY CLIENT ID: %s\n", cfg.WebIdentityClientId)
		fmt.Printf("WEB IDENTITY REDIRECT URI: %s\n", cfg.WebIdentityRedirectUri)
		fmt.Printf("WEB IDENTITY USERNAME: %s\n", cfg.WebIdentityUsername)
		fmt.Printf("JUMP ROLE ARN: %s\n", cfg.JumpRoleArn)
	}
}

func checkEnv() {
	envAk := os.Getenv("AWS_ACCESS_KEY_ID")
	envSt := os.Getenv("AWS_SESSION_TOKEN")

	if len(envAk) > 0 && len(envSt) > 0 {
		if strings.HasPrefix(envAk, "AKIA") {
			log.Error("detected static access key env var along with session token env var, this is invalid")
		} else {
			log.Info("environment variables appear sane")
		}
	}
}

func checkRegion(region string) {
	// Check that region is set
	if len(region) < 1 {
		log.Error("region is not set, it must be specified in the config file or as an environment variable")
	} else {
		log.Info("region is configured in profile or environment variable")
	}
}

func checkProfileCfg(cfg *config.AwsConfig) {
	if len(cfg.SamlUrl) > 0 && len(cfg.WebIdentityUrl) > 0 {
		log.Error("found SAML and Web Identity (OIDC) endpoint urls set, this is invalid")
	}

	if len(cfg.ProfileName) > 0 {
		if len(cfg.SamlUrl) > 0 || len(cfg.WebIdentityUrl) > 0 {
			checkExternalProviderConfig(cfg)
		} else {
			checkIamConfig(cfg)
		}
	}
}

func checkExternalProviderConfig(cfg *config.AwsConfig) {
	if len(cfg.RoleArn) < 1 {
		log.Error("role_arn is a required parameter when using external identity providers")
	}

	if len(cfg.SamlUrl) > 0 {
		checkProvider(cfg.SamlUrl)
	} else {
		checkProvider(cfg.WebIdentityUrl)
		if len(cfg.WebIdentityClientId) < 1 || len(cfg.WebIdentityRedirectUri) < 1 {
			log.Error("missing web_identity_client_id and/or web_identity_redirect_uri configuration")
		}
	}
}

func checkIamConfig(cfg *config.AwsConfig) {
	// iam profile checks
	var cfgCreds bool

	if len(cfg.RoleArn) > 0 {
		if len(cfg.SrcProfile) < 1 || cfg.SourceProfile() == nil {
			log.Errorf("missing source_profile configuration for profile '%s'", cfg.ProfileName)
			return
		}

		// source_profile name must exist in the credentials file when using IAM profiles
		cfgCreds = checkCredentialProfile(cfg.SrcProfile)
	} else {
		// not a profile with a role, must have matching section in creds file
		cfgCreds = checkCredentialProfile(cfg.ProfileName)
	}

	// check for profile creds and env var creds at the same time
	envAk := os.Getenv("AWS_ACCESS_KEY_ID")
	if cfgCreds && len(envAk) > 0 {
		log.Error("detected AWS credential environment variables and profile credentials, this may confuse aws-runas")
	} else {
		log.Info("credentials appear sane")
	}
}

func checkProvider(url string) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, url, http.NoBody) //nolint:gosec
	if err != nil {
		log.Errorf("error creating http request: %v", err)
		return
	}

	var res *http.Response
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Errorf("error communicating with external provider endpoint: %v", err)
	}
	defer res.Body.Close()

	// default http client chases redirects automatically
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusMethodNotAllowed {
		log.Warningf("http status %s when communicating with external provider endpoint", res.Status)
	}
}

func checkCredentialProfile(profile string) bool {
	src := defaults.SharedCredentialsFilename()
	if v, ok := os.LookupEnv("AWS_SHARED_CREDENTIALS_FILE"); ok {
		src = v
	}

	f, err := ini.Load(src)
	if err != nil {
		log.Errorf("error loading credentials file: %v", err)
		return false
	}

	s, err := f.GetSection(profile)
	if err != nil {
		log.Errorf("error loading profile credentials: %v", err)
		return false
	}

	if !s.HasKey("aws_access_key_id") || !s.HasKey("aws_secret_access_key") {
		log.Errorf("incomplete or missing credentials for profile '%s'", profile)
		return false
	}

	log.Info("profile credentials appear sane")
	return true
}

func checkTime() {
	// AWS requires that the timestamp in API requests be within 5 minutes of the time at
	// the service endpoint. Ensure our local clock is within 5 minutes of an NTP source
	maxDrift := 5 * time.Minute
	warnDrift := 3 * time.Minute

	nTime, err := ntpTime()
	if err != nil {
		log.Errorf("error checking ntp: %v", err)
		return
	}

	tLocal := time.Now()
	drift := nTime.Sub(tLocal)
	log.Debugf("ntp: %+v, local: %+v, drift: %+v", nTime.Unix(), tLocal.Unix(), drift)

	switch d := math.Abs(drift.Seconds()); {
	case d >= maxDrift.Seconds():
		log.Errorf("Local time drift is more than %v, AWS API requests will be rejected", maxDrift.Truncate(time.Minute))
	case d > warnDrift.Seconds():
		log.Warningf("Local time drift is more than %v seconds, check system time", warnDrift.Truncate(time.Minute))
	default:
		log.Info("system time is within spec")
	}
}

func ntpTime() (time.Time, error) {
	var t time.Time
	var err error

	deadlineDuration := 200 * time.Millisecond
	gotResponse := false

	for !gotResponse {
		if deadlineDuration > 10*time.Second {
			return time.Time{}, fmt.Errorf("retry attempt limit exceeded")
		}

		t, err = fetchTime(deadlineDuration)
		if err != nil {
			switch e := err.(type) {
			case *net.OpError:
				if e.Timeout() || e.Temporary() {
					deadlineDuration = (deadlineDuration * 3) / 2
					log.Debugf("Retryable error %v, deadline duration %v", e, deadlineDuration)
					continue
				} else {
					return t, e
				}
			default:
				return t, e
			}
		}
		gotResponse = true
	}

	return t, nil
}

// REF: https://medium.com/learning-the-go-programming-language/lets-make-an-ntp-client-in-go-287c4b9a969f.
func fetchTime(deadline time.Duration) (time.Time, error) {
	// epoch times between NTP and Unix time are offset by this much
	// REF: https://tools.ietf.org/html/rfc5905#section-6 (Figure 4)
	var ntpUnixOffsetSec uint32 = 2208988800

	c, err := net.Dial("udp", "pool.ntp.org:123")
	if err != nil {
		return time.Time{}, err
	}
	defer c.Close()

	if deadline > 0 {
		if err := c.SetReadDeadline(time.Now().Add(deadline)); err != nil {
			return time.Time{}, err
		}
	}

	// NTPv3 client request packet
	if err := binary.Write(c, binary.BigEndian, &ntpPacket{Settings: 0x1B}); err != nil {
		return time.Time{}, err
	}

	resp := new(ntpPacket)
	if err := binary.Read(c, binary.BigEndian, resp); err != nil {
		return time.Time{}, err
	}

	return time.Unix(int64(resp.TxTimeSec-ntpUnixOffsetSec), (int64(resp.TxTimeFrac)*1e9)>>32), nil
}

type ntpPacket struct {
	Settings       uint8  // leap yr indicator, ver number, and mode
	Stratum        uint8  // stratum of local clock
	Poll           int8   // poll exponent
	Precision      int8   // precision exponent
	RootDelay      uint32 // root delay
	RootDispersion uint32 // root dispersion
	ReferenceID    uint32 // reference id
	RefTimeSec     uint32 // reference timestamp sec
	RefTimeFrac    uint32 // reference timestamp fractional
	OrigTimeSec    uint32 // origin time secs
	OrigTimeFrac   uint32 // origin time fractional
	RxTimeSec      uint32 // receive time secs
	RxTimeFrac     uint32 // receive time frac
	TxTimeSec      uint32 // transmit time secs
	TxTimeFrac     uint32 // transmit time frac
}
