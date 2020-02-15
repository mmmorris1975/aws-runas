package main

import (
	"aws-runas/lib/config"
	"encoding/binary"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	cfglib "github.com/mmmorris1975/aws-config/config"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// RunDiagnostics will sanity check various configuration items, print errors as we find them
func runDiagnostics(c *config.AwsConfig) error {
	log.Debugf("Diagnostics")

	checkEnv()
	checkRegion(c)
	p := checkProfile(profile)

	if p == c.RoleArn {
		// profile was a Role ARN, config will be whatever was explicitly passed + env var config,
		// and possibly a default config, if the config file exists and has the default section
		log.Info("Role ARN provided as the profile, configuration file will not be checked")
	} else {
		// profile is a config profile name
		checkProfileCfg(p, c)
	}

	if err := checkTime(); err != nil {
		return err
	}

	printConfig(p, c)

	return nil
}

func checkEnv() {
	envAk := os.Getenv("AWS_ACCESS_KEY_ID")
	envSt := os.Getenv("AWS_SESSION_TOKEN")

	if len(envAk) > 0 && len(envSt) > 0 {
		if strings.HasPrefix(envAk, "AKIA") {
			log.Errorf("detected static access key env var along with session token env var, this is invalid")
		} else {
			log.Info("environment variables appear sane")
		}
	}
}

func checkRegion(c *config.AwsConfig) {
	// Check that region is set
	if len(c.Region) < 1 {
		log.Errorf("region is not set, it must be specified in the config file or as an environment variable")
	} else {
		log.Info("region is configured in profile or environment variable")
	}
}

func checkProfile(p *string) string {
	if p == nil || len(*p) < 1 {
		log.Warn("No profile specified, will only check default section. Provide a profile name for more validation")
		p = aws.String("default")
	}
	return *p
}

func checkProfileCfg(p string, c *config.AwsConfig) {
	if len(p) > 0 {
		if c.SamlAuthUrl != nil && len(c.SamlAuthUrl.String()) > 0 {
			// do saml specific things
			if len(c.RoleArn) < 1 {
				log.Error("role_arn is a required parameter when using SAML integration")
			}

			u, err := http.Head(c.SamlAuthUrl.String())
			if err != nil {
				log.Errorf("error communicating with SAML metadata url: %v", err)
			}

			if u.StatusCode != http.StatusOK {
				log.Errorf("http status code %d when communicating with SAML metadaurl", u.StatusCode)
			}
		} else {
			var cfgCreds bool

			// do iam specific things
			if len(c.RoleArn) > 0 {
				if len(c.SourceProfile) < 1 {
					log.Errorf("missing source_profile configuration for profile '%s'", p)
					return
				}
				// source_profile name must exist in the credentials file when using IAM profiles
				cfgCreds = checkCredentialProfile(c.SourceProfile)
			} else {
				// not a profile with a role, must have matching section in creds file
				cfgCreds = checkCredentialProfile(p)
			}

			// check for profile creds and env var creds at the same time
			envAk := os.Getenv("AWS_ACCESS_KEY_ID")
			if cfgCreds && len(envAk) > 0 {
				log.Error("detected AWS credential environment variables and profile credentials, this may confuse aws-runas")
			} else {
				log.Info("credentials appear sane")
			}
		}
	}
}

func checkCredentialProfile(profile string) bool {
	cfg, err := cfglib.NewIniCredentialProvider(nil)
	if err != nil {
		log.Errorf("error loading credentials file: %v", err)
		return false
	}

	p, err := cfg.Profile(profile)
	if err != nil {
		log.Errorf("error loading profile credentials: %v", err)
		return false
	}

	if !p.HasKey("aws_access_key_id") || !p.HasKey("aws_secret_access_key") {
		log.Errorf("incomplete or missing credentials for profile '%s'", profile)
		return false
	}

	log.Info("profile credentials appear sane")
	return true
}

func checkTime() error {
	// AWS requires that the timestamp in API requests be within 5 minutes of the time at
	// the service endpoint. Ensure our local clock is within 5 minutes of an NTP source
	maxDrift := 5 * time.Minute
	warnDrift := 3 * time.Minute

	nTime, err := ntpTime()
	if err != nil {
		log.Debugf("error checking ntp: %v", err)
		return err
	}

	tLocal := time.Now()
	drift := nTime.Sub(tLocal)
	log.Debugf("ntp: %+v, local: %+v, drift: %+v", nTime.Unix(), tLocal.Unix(), drift)

	if math.Abs(drift.Seconds()) >= maxDrift.Seconds() {
		log.Errorf("Local time drift is more than %v, AWS API requests will be rejected", maxDrift.Truncate(time.Minute))
		return nil
	}

	if math.Abs(drift.Seconds()) > warnDrift.Seconds() {
		log.Warnf("Local time drift is more than %v seconds, check system time", warnDrift.Truncate(time.Minute))
		return nil
	}

	log.Info("system time is within spec")
	return nil
}

func printConfig(p string, c *config.AwsConfig) {
	fmt.Printf("PROFILE: %s\n", p)
	fmt.Printf("REGION: %s\n", c.Region)
	fmt.Printf("SOURCE PROFILE: %s\n", c.SourceProfile)
	fmt.Printf("SESSION TOKEN DURATION: %s\n", c.SessionTokenDuration)
	fmt.Printf("MFA SERIAL: %s\n", c.MfaSerial)
	fmt.Printf("ROLE ARN: %s\n", c.RoleArn)
	fmt.Printf("EXTERNAL ID: %s\n", c.ExternalId)
	fmt.Printf("ASSUME ROLE CREDENTIAL DURATION: %s\n", c.CredentialsDuration)

	if c.SamlAuthUrl != nil && len(c.SamlAuthUrl.String()) > 0 {
		fmt.Printf("SAML METADATA URL: %s\n", c.SamlAuthUrl.String())
		fmt.Printf("SAML USERNAME: %s\n", c.SamlUsername)
		fmt.Printf("JUMP ROLE ARN: %s\n", c.JumpRoleArn.String())
	}
}

// NTP client bits below
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

func ntpTime() (time.Time, error) {
	var t time.Time
	var err error

	deadlineDuration := 200 * time.Millisecond
	gotResponse := false

	for !gotResponse {
		if deadlineDuration > 10*time.Second {
			gotResponse = true
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

// REF: https://medium.com/learning-the-go-programming-language/lets-make-an-ntp-client-in-go-287c4b9a969f
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
