package lib

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/service/sts"
	"os/user"
	"regexp"
	"time"
)

const (
	// ASSUME_ROLE_MIN_DURATION is the AWS SDK minimum assume role credentials duration
	ASSUME_ROLE_MIN_DURATION = SESSION_TOKEN_MIN_DURATION
	// ASSUME_ROLE_MAX_DURATION is the AWS SDK maximum assume role credentials duration
	ASSUME_ROLE_MAX_DURATION = time.Duration(12 * time.Hour)
	// ASSUME_ROLE_DEFAULT_DURATION is the AWS SDK default assume role credentials duration
	ASSUME_ROLE_DEFAULT_DURATION = time.Duration(1 * time.Hour)
)

// AssumeRoleProvider is the interface defining the methods needed to manage AWS assume role credentials
type AssumeRoleProvider interface {
	SessionTokenProvider
	stscreds.AssumeRoler
}

type assumeRoleProvider struct {
	sessionTokenProvider
}

// NewAssumeRoleProvider creates a new AssumeRoleProvider for the given profile.
// Unspecified credential durations will be set to their default value. Values
// outside of the min and max range will be set to the respective min/max values.
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
	opts.cacheFileName = fmt.Sprintf(".aws_assume_role_%s", profile.Name)

	p.cachedCredentialsProvider = NewCachedCredentialsProvider(profile, opts)
	p.log = NewLogger("aws-runas.AssumeRoleProvider", opts.LogLevel)

	return p
}

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

// AssumeRole performs an AWS AssumeRole API call to get the Assume Role credentials bypassing
// any cached credentials, unless MFA is being used and the assume role duration is 1 hour
// or less. (Use cached session tokens to call assume role instead to limit MFA re-entry)
//
// implements sts.AssumeRoler
func (p *assumeRoleProvider) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	profile := p.profile

	if input == nil && profile != nil {
		input = new(sts.AssumeRoleInput)
		input.RoleArn = aws.String(profile.RoleArn.String())
		input.RoleSessionName = p.validateSessionName(profile.RoleSessionName)

		if len(profile.ExternalId) > 0 {
			input.ExternalId = aws.String(profile.ExternalId)
		}
	}

	if len(p.opts.MfaSerial) > 0 {
		input.SerialNumber = aws.String(p.opts.MfaSerial)
	} else if len(profile.MfaSerial) > 0 {
		input.SerialNumber = aws.String(profile.MfaSerial)
	}

	if p.opts.CredentialDuration > 0 {
		input.DurationSeconds = p.validateDuration(p.opts.CredentialDuration)
	} else {
		input.DurationSeconds = p.validateDuration(profile.CredDuration)
	}

	s := sts.New(p.sess)
	if input.SerialNumber != nil && len(*input.SerialNumber) > 0 {
		if *input.DurationSeconds <= int64(ASSUME_ROLE_DEFAULT_DURATION.Seconds()) && profile != nil {
			// If we're using MFA, and the duration is less than the 1 hour limit AWS imposes on assume
			// role credentials retrieved using session token credentials, use session token creds before
			// doing assume role.  Preserves desired behavior from pre-1.0 versions to limit MFA re-entry
			o := new(CachedCredentialsProviderOptions)
			o.CredentialDuration = p.profile.SessionDuration
			o.LogLevel = p.opts.LogLevel
			o.MfaSerial = p.opts.MfaSerial

			p.log.Debugf("REFRESHING USING SESSION CREDENTIALS")
			sesProvider := NewSessionTokenProvider(profile, o)
			s = sts.New(p.sess, &aws.Config{Credentials: credentials.NewCredentials(sesProvider)})
			input.SerialNumber = nil
		} else {
			p.log.Debugf("PROMPTING FOR MFA CODE")
			input.TokenCode = aws.String(PromptForMfa())
		}
	}

	p.log.Debugf("AR INPUT: %+v", input)
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
		p.log.Debug("Setting default assume role duration")
		return aws.Int64(int64(ASSUME_ROLE_DEFAULT_DURATION.Seconds()))
	}

	dur := time.Duration(d).Seconds()
	if dur < ASSUME_ROLE_MIN_DURATION.Seconds() {
		p.log.Debug("Assume role duration too short, adjusting to min value")
		return aws.Int64(int64(ASSUME_ROLE_MIN_DURATION.Seconds()))
	}

	if dur > ASSUME_ROLE_MAX_DURATION.Seconds() {
		p.log.Debug("Assume role duration too long, adjusting to max value")
		return aws.Int64(int64(ASSUME_ROLE_MAX_DURATION.Seconds()))
	}

	return aws.Int64(int64(dur))
}
