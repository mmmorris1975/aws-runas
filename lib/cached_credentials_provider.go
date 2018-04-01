package lib

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/mbndr/logo"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// AWS SDK minimum session token duration
	SESSION_TOKEN_MIN_DURATION = time.Duration(15 * time.Minute)
	// AWS SDK maximum session token duration
	SESSION_TOKEN_MAX_DURATION = time.Duration(36 * time.Hour)
	// AWS SDK default session token duration
	SESSION_TOKEN_DEFAULT_DURATION = time.Duration(12 * time.Hour)
	// AWS SDK minimum assume role credentials duration
	ASSUME_ROLE_MIN_DURATION = SESSION_TOKEN_MIN_DURATION
	// AWS SDK maximum assume role credentials duration
	ASSUME_ROLE_MAX_DURATION = time.Duration(12 * time.Hour)
	// AWS SDK default assume role credentials duration
	ASSUME_ROLE_DEFAULT_DURATION = time.Duration(1 * time.Hour)
)

// A credentials.Value compatible set of credentials with the
// addition of expiration information, able to be serialized to a file
type CachableCredentials struct {
	credentials.Value
	credentials.Expiry `json:"-"` // do not marshal
	Expiration         int64
}

// Interface defining methods required to cache credentials
// and check for validity (non-expiration)
type CachedCredentialsProvider interface {
	credentials.Provider
	Store() error
	ExpirationTime() time.Time
	CacheFile() string
}

// Interface defining the methods needed to store AWS
// session token credentials, and the ability to call
// AssumeRole() with said credentials.
type SessionTokenProvider interface {
	CachedCredentialsProvider
	stscreds.AssumeRoler
}

// Constructor options for a SessionTokenProvider
type SessionTokenProviderOptions struct {
	LogLevel             logo.Level
	SessionTokenDuration time.Duration
	MfaSerial            string
}

// Create a new SessionTokenProvider for the given profile.  Unspecified
// session token and assume role credential durations will be set to their
// respective default values.  Values outside of the min and max range for
// a given credential type will be set to the respective min/max values.
//
// If the RoleArn option is provided, it will be validated to ensure it's a
// properly formatted AWS IAM arn.  This value will override any value
// set in the profile.
//
// If the MfaSerial option is provided, its value will be provided to the
// call to create the session token credentials.  This value will override
// any value set in the profile.
//
// The credential cache file will reside in the directory for the default
// config file name, with a file name of .aws_session_token_<profile>
// The specific value can be obtained via a call to CacheFile()
func NewSessionTokenProvider(profile *AWSProfile, opts *SessionTokenProviderOptions) (SessionTokenProvider, error) {
	p := new(awsAssumeRoleProvider)
	p.ProviderName = "CachedCredentialsProvider"

	if err := p.setAttrs(profile, opts); err != nil {
		return nil, err
	}
	p.log.Debugf("NewSessionTokenProvider() with options: %+v", opts)

	// Create a session based on the configured source profile, otherwise
	// AWS SDK takes over and tries to do the assume role call with the
	// user's credentials vs. session token.
	p.sess = AwsSession(profile.SourceProfile)

	p.log.Debugf("NewSessionTokenProvider(): %+v", p)
	return p, nil
}

type awsAssumeRoleProvider struct {
	log                  *logo.Logger
	sessionTokenDuration time.Duration
	cacheFile            string
	profile              *AWSProfile
	creds                *CachableCredentials
	sess                 *session.Session
	ProviderName         string
}

// Check if a set of credentials have expired (or are within the
// expiration window).  Default case is to return true so that only
// verified non-expired credentials will report as not expired.
//
// satisfies credentials.Provider
func (p *awsAssumeRoleProvider) IsExpired() bool {
	c := p.creds

	if c == nil {
		return true
	}

	stat, err := os.Stat(p.cacheFile)
	if err == nil {
		exp_t := expirationTime(c.Expiration)
		window := exp_t.Sub(stat.ModTime()) / 10
		c.SetExpiration(exp_t, window)
	}

	return p.creds.IsExpired()
}

// Retrieve the session token credentials from the cache.  If the
// credentials are expired, or there is no cache, a new set of
// session token credentials will be created and stored.
//
// On error, the error return value will be non-nil with an empty
// credentials.Value
//
// satisfies credentials.Provider
func (p *awsAssumeRoleProvider) Retrieve() (credentials.Value, error) {
	// lazy load credentials
	c, err := p.credsFromFile()
	if err == nil {
		p.log.Debugf("Found cached session token credentials")
		p.creds = c
	}

	if p.IsExpired() {
		p.log.Debugf("Detected expired or unset session token credentials, refreshing")
		creds, err := p.sessionToken()
		if err != nil {
			return credentials.Value{}, err
		}

		c = &CachableCredentials{
			Expiration: creds.Expiration.Unix(),
			Value: credentials.Value{
				AccessKeyID:     *creds.AccessKeyId,
				SecretAccessKey: *creds.SecretAccessKey,
				SessionToken:    *creds.SessionToken,
				ProviderName:    p.ProviderName,
			},
		}
		p.creds = c
		p.Store()
	}

	return p.creds.Value, nil
}

// Write the session token credentials to the cache
func (p *awsAssumeRoleProvider) Store() error {
	data, err := json.Marshal(p.creds)
	if err != nil {
		return err
	}
	p.log.Debugf("Marshaled session credentials:\n%+s", data)

	if err := os.MkdirAll(filepath.Dir(p.cacheFile), 0755); err != nil {
		return err
	}

	if err := ioutil.WriteFile(p.cacheFile, data, 0600); err != nil {
		return err
	}
	p.log.Debugf("Wrote credentials to: %s", p.cacheFile)

	return nil
}

// Return the absolute expiration time of the credentials.  The value
// returned does not account for any window prior to the credential
// expiration where the provider may automatically attempt to refresh
// the session token credentials.  If no credentials can be found, the
// Unix epoch time will be returned.
func (p *awsAssumeRoleProvider) ExpirationTime() time.Time {
	defaultTime := time.Unix(0, 0)
	if p.creds == nil {
		return defaultTime
	}
	return expirationTime(p.creds.Expiration)
}

// Return the absolute path to the file holding the session token
// credentials for this profile
func (p *awsAssumeRoleProvider) CacheFile() string {
	return p.cacheFile
}

// Perform an AWS AssumeRole API call to get the Assume Role credentials
// using the cached (or refreshed) session token credentials
//
// implements sts.AssumeRoler
func (p *awsAssumeRoleProvider) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	if err := p.validateArn(input.RoleArn); err != nil {
		return nil, err
	}

	input.RoleSessionName = p.validateRoleSessionName(input.RoleSessionName)
	input.DurationSeconds = p.validateRoleDuration(input.DurationSeconds)

	// Input SerialNumber field not required here, if necessary it is part of the
	// SessionToken credentials generated by this provider
	input.SerialNumber = aws.String("")

	s := sts.New(p.sess, &aws.Config{Credentials: credentials.NewCredentials(p)})
	return s.AssumeRole(input)
}

func (p *awsAssumeRoleProvider) credsFromFile() (*CachableCredentials, error) {
	c := new(CachableCredentials)

	data, err := ioutil.ReadFile(p.cacheFile)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}

	return c, nil
}

func (p *awsAssumeRoleProvider) sessionToken() (*sts.Credentials, error) {
	tokDuration := aws.Int64(int64(p.sessionTokenDuration.Seconds()))
	in := sts.GetSessionTokenInput{DurationSeconds: tokDuration}

	if len(p.profile.MfaSerial) > 0 {
		in.SerialNumber = aws.String(p.profile.MfaSerial)
		in.TokenCode = aws.String(PromptForMfa())
	}

	s := sts.New(p.sess)
	res, err := s.GetSessionToken(&in)
	if err != nil {
		return nil, err
	}
	return res.Credentials, nil
}

func (p *awsAssumeRoleProvider) setAttrs(profile *AWSProfile, opts *SessionTokenProviderOptions) error {
	logger := logo.NewSimpleLogger(os.Stderr, opts.LogLevel, "aws-runas.CachedCredentialsProvider", true)
	p.log = logger

	if opts.SessionTokenDuration < 1 {
		p.log.Debug("Setting default session token duration")
		opts.SessionTokenDuration = SESSION_TOKEN_DEFAULT_DURATION
	} else if opts.SessionTokenDuration < SESSION_TOKEN_MIN_DURATION {
		p.log.Debug("Session token duration too short, adjusting to min value")
		opts.SessionTokenDuration = SESSION_TOKEN_MIN_DURATION
	} else if opts.SessionTokenDuration > SESSION_TOKEN_MAX_DURATION {
		p.log.Debug("Session token duration too long, adjusting to max value")
		opts.SessionTokenDuration = SESSION_TOKEN_MAX_DURATION
	}
	p.sessionTokenDuration = opts.SessionTokenDuration

	if len(opts.MfaSerial) > 0 {
		profile.MfaSerial = opts.MfaSerial
	}
	p.profile = profile

	cacheDir := filepath.Dir(AwsConfigFile())
	p.cacheFile = filepath.Join(cacheDir, fmt.Sprintf(".aws_session_token_%s", profile.SourceProfile))

	return nil
}

// Validate that the AssumeRole DurationSeconds value is something sane
// by converting to a time.Duration and checking that it falls within bounds
// unset value will be defaulted
func (p *awsAssumeRoleProvider) validateRoleDuration(d *int64) *int64 {
	if d == nil {
		return aws.Int64(int64(ASSUME_ROLE_DEFAULT_DURATION.Seconds()))
	}

	dur := time.Duration(*d) * time.Second
	if dur < ASSUME_ROLE_MIN_DURATION {
		d = aws.Int64(int64(ASSUME_ROLE_MIN_DURATION.Seconds()))
	}

	if dur > ASSUME_ROLE_MAX_DURATION {
		d = aws.Int64(int64(ASSUME_ROLE_MAX_DURATION.Seconds()))
	}

	return d
}

// RoleArn is a required AssumeRole API parameter, validate it exists
// and is a proper IAM ARN
func (p *awsAssumeRoleProvider) validateArn(a *string) error {
	if a == nil || len(*a) < 1 {
		return fmt.Errorf("nil RoleArn input")
	} else {
		// validate ARN
		if _, err := arn.Parse(*a); err != nil {
			return err
		}

		if !strings.HasPrefix(*a, IAM_ARN) {
			return fmt.Errorf("RoleArn is not an IAM ARN")
		}
	}
	return nil
}

// RoleSessionName is a required attribute, per sdk docs, if unset one will be
// generated, otherwise the value is passed through
func (p *awsAssumeRoleProvider) validateRoleSessionName(n *string) *string {
	if n == nil || len(*n) < 1 {
		username := "__"

		u, err := user.Current()
		if err != nil {
			p.log.Debugf("Error getting user details: %v", err)
		} else {
			// On Windows, this could return DOMAIN\user, and '\' is not a valid character for RoleSessionName
			// AWS API docs say that regex [[:word:]=,.@-] is the valid characters for RoleSessionName
			re := regexp.MustCompile("[^[:word:]=,.@-]")
			username = re.ReplaceAllLiteralString(u.Username, "_")
		}

		n = aws.String(fmt.Sprintf("AWS-RUNAS-%s-%d", username, time.Now().Unix()))
		if p.log != nil {
			p.log.Debugf("Setting AssumeRole session name to: %s", *n)
		}
	}
	return n
}

func expirationTime(t int64) time.Time {
	return time.Unix(t, 0)
}
