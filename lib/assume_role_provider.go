package lib

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/mbndr/logo"
	"os"
	"os/user"
	"regexp"
	"time"
)

const (
	// AWS SDK minimum assume role credentials duration
	ASSUME_ROLE_MIN_DURATION = SESSION_TOKEN_MIN_DURATION
	// AWS SDK maximum assume role credentials duration
	ASSUME_ROLE_MAX_DURATION = time.Duration(12 * time.Hour)
	// AWS SDK default assume role credentials duration
	ASSUME_ROLE_DEFAULT_DURATION = time.Duration(1 * time.Hour)
)

// Interface defining the methods needed to manage AWS assume role credentials
type AssumeRoleProvider interface {
	credentials.Provider
	stscreds.AssumeRoler
}

type assumeRoleProvider struct {
	sessionTokenProvider
}

// Create a new AssumeRoleProvider for the given profile. Unspecified
// credential durations will be set to their default value. Values outside
// of the min and max range will be set to the respective min/max values.
// If the CredentialDuration option is set, its value will override any value
// set in the profile. Any value set for the DurationSeconds field of the
// AssumeRoleInput will be given highest priority.
//
// If the MfaSerial option is provided, its value will be provided to the
// call to create the assume role credentials.  This value will override
// any value set in the profile.  Any valid value set for the SerialNumber
// field of the AssumeRoleInput will be given the highest priority.
//
// The credential cache file will reside in the directory for the default
// config file name, with a file name of .aws_session_token_<profile>
func NewAssumeRoleProvider(profile *AWSProfile, opts *CachedCredentialsProviderOptions) AssumeRoleProvider {
	p := new(assumeRoleProvider)
	p.providerName = "AssumeRoleProvider"

	if opts == nil {
		opts = new(CachedCredentialsProviderOptions)
	}
	opts.cacheFilePrefix = ".aws_assume_role"
	p.log = logo.NewSimpleLogger(os.Stderr, opts.LogLevel, "aws-runas.AssumeRoleProvider", true)

	p.CachedCredentialsProvider = NewCachedCredentialsProvider(profile, opts)

	return p
}

//func (p *assumeRoleProvider) IsExpired() bool {
//
//}

// Retrieve the assume role credentials from the cache.  If the
// credentials are expired, or there is no cache, a new set of
// assume role credentials will be created and stored.
//
// On error, the error return value will be non-nil with an empty
// credentials.Value
//
// satisfies credentials.Provider
func (p *assumeRoleProvider) Retrieve() (credentials.Value, error) {
	// lazy load credentials
	c, err := p.cacher.Fetch()
	if err == nil {
		p.log.Debugf("Found cached assume role credentials")
		p.creds = c
	}

	if p.IsExpired() {
		p.log.Debugf("Detected expired or unset assume role credentials, refreshing")
		out, err := p.AssumeRole(nil)
		if err != nil {
			return credentials.Value{}, err
		}
		p.log.Debugf("ASSUME ROLE OUTPUT: %+v", out)
		creds := out.Credentials

		c = &CachableCredentials{
			Expiration: creds.Expiration.Unix(),
			Value: credentials.Value{
				AccessKeyID:     *creds.AccessKeyId,
				SecretAccessKey: *creds.SecretAccessKey,
				SessionToken:    *creds.SessionToken,
				ProviderName:    p.providerName,
			},
		}
		p.creds = c
		p.cacher.Store(c)
	}

	p.log.Debugf("ASSUME ROLE CREDENTIALS: %+v", p.creds)
	return p.creds.Value, nil
}

// Perform an AWS AssumeRole API call to get the Assume Role credentials
// bypassing any the cached credentials
//
// implements sts.AssumeRoler
func (p *assumeRoleProvider) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	if input == nil && p.profile != nil {
		profile := p.profile

		input = new(sts.AssumeRoleInput)
		input.SerialNumber = aws.String(profile.MfaSerial)
		input.ExternalId = aws.String(profile.ExternalId)
		input.RoleArn = aws.String(profile.RoleArn.String())
		input.RoleSessionName = p.validateSessionName(profile.RoleSessionName)
		input.DurationSeconds = p.validateDuration(profile.CredDuration) // What about opts.CredentialDuration?

		if len(p.opts.MfaSerial) > 0 {
			input.SerialNumber = aws.String(p.opts.MfaSerial)
		}

		if p.opts.CredentialDuration > 0 {
			input.DurationSeconds = p.validateDuration(p.opts.CredentialDuration)
		}
	}

	if input.SerialNumber != nil && len(*input.SerialNumber) > 0 {
		input.TokenCode = aws.String(PromptForMfa())
	}

	s := sts.New(p.sess)
	return s.AssumeRole(input)
}

func (p *assumeRoleProvider) validateSessionName(n string) *string {
	if len(n) < 1 {
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

		n = fmt.Sprintf("AWS-RUNAS-%s-%d", username, time.Now().Unix())
		if p.log != nil {
			p.log.Debugf("Setting AssumeRole session name to: %s", n)
		}
	}
	return aws.String(n)
}

func (p *assumeRoleProvider) validateDuration(d time.Duration) *int64 {
	if d == 0 {
		return aws.Int64(int64(ASSUME_ROLE_DEFAULT_DURATION.Seconds()))
	}

	dur := time.Duration(d).Seconds()
	if dur < ASSUME_ROLE_MIN_DURATION.Seconds() {
		return aws.Int64(int64(ASSUME_ROLE_MIN_DURATION.Seconds()))
	}

	if dur > ASSUME_ROLE_MAX_DURATION.Seconds() {
		return aws.Int64(int64(ASSUME_ROLE_MAX_DURATION.Seconds()))
	}

	return aws.Int64(int64(dur))
}
