package lib

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/mbndr/logo"
	"os/user"
	"path/filepath"
	"regexp"
	"time"
)

type CachingSessionTokenProvider struct {
	CredentialsCacherProvider
	Profile   string
	Duration  time.Duration
	MfaSerial string
	Logger    *logo.Logger
}

func (p *CachingSessionTokenProvider) CacheFile() string {
	p.Logger.Debug("In CacheFile()")
	cacheDir := filepath.Dir(defaults.SharedCredentialsFilename())
	cacheFile := filepath.Join(cacheDir, fmt.Sprintf(".aws_session_token_%s", p.Profile))

	p.Logger.Debugf("CREDENTIAL CACHE FILE: %s", cacheFile)
	return cacheFile
}

// Satisfies credentials.Provider
func (p *CachingSessionTokenProvider) Retrieve() (credentials.Value, error) {
	p.Logger.Debug("In Retrieve()")
	p.CredentialsCacherProvider.CacheFilename = p.CacheFile()
	creds, _ := p.CredentialsCacherProvider.Retrieve() // TODO let errors fall through?

	if p.IsExpired() {
		p.Logger.Debug("Detected expired credentials")
		dur_secs := int64(p.Duration.Seconds())
		input := sts.GetSessionTokenInput{DurationSeconds: &dur_secs}

		if len(p.MfaSerial) > 0 {
			p.Logger.Debug("MfaSerial passed, prompting for code")
			// Prompt for MFA code
			var mfa_code string
			fmt.Print("Enter MFA Code: ")
			fmt.Scanln(&mfa_code)

			input.SerialNumber = &p.MfaSerial
			input.TokenCode = &mfa_code
		}

		sess := session.Must(session.NewSessionWithOptions(
			session.Options{
				SharedConfigState: session.SharedConfigEnable,
				Profile:           p.Profile,
			}))

		s := sts.New(sess)
		res, err := s.GetSessionToken(&input)
		if err != nil {
			return credentials.Value{}, err
		}

		c := CacheableCredentials{
			AccessKeyId:     *res.Credentials.AccessKeyId,
			SecretAccessKey: *res.Credentials.SecretAccessKey,
			SessionToken:    *res.Credentials.SessionToken,
			Expiration:      (*res.Credentials.Expiration).Unix(),
		}
		p.Logger.Debug("Storing new credentials in cache")
		p.CredentialsCacherProvider.Store(&c)
		creds, _ = p.CredentialsCacherProvider.Retrieve()
	}

	p.Logger.Debugf("SESSION TOKEN CREDENTIALS: %+v", creds)
	return creds, nil
}

// Satisfies credentials.Provider
func (p *CachingSessionTokenProvider) IsExpired() bool {
	p.Logger.Debug("In IsExpired()")
	expired := true
	expired = p.CredentialsCacherProvider.IsExpired()

	p.Logger.Debugf("EXPIRED: %t", expired)
	return expired
}

func (p *CachingSessionTokenProvider) AssumeRole(profile_cfg *AWSProfile) (credentials.Value, error) {
	p.Logger.Debug("In AssumeRole()")
	username := "__"
	user, err := user.Current()
	if err == nil {
		// On Windows, this could return DOMAIN\user, and '\' is not a valid character for RoleSessionName
		// AWS API docs say that regex [[:word:]=,.@-] is the valid characters for RoleSessionName
		re := regexp.MustCompile("[^[:word:]=,.@-]")
		username = re.ReplaceAllLiteralString(user.Username, "_")
	}

	sesName := aws.String(fmt.Sprintf("AWS-RUNAS-%s-%d", username, time.Now().Unix()))
	p.Logger.Debugf("Setting AssumeRole session name to: %s", *sesName)
	input := sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(int64(3600)),
		RoleArn:         aws.String(profile_cfg.RoleArn),
		RoleSessionName: sesName,
	}

	creds, err := p.Retrieve()
	if err != nil {
		return credentials.Value{}, err
	}

	sesOpts := session.Options{
		Profile:           profile_cfg.SourceProfile,
		SharedConfigState: session.SharedConfigEnable,
		Config:            aws.Config{Credentials: credentials.NewStaticCredentialsFromCreds(creds)},
	}
	s := session.Must(session.NewSessionWithOptions(sesOpts))
	sts := sts.New(s)
	res, err := sts.AssumeRole(&input)
	if err != nil {
		return credentials.Value{}, err
	}

	c := res.Credentials
	v := credentials.Value{
		AccessKeyID:     *c.AccessKeyId,
		SecretAccessKey: *c.SecretAccessKey,
		SessionToken:    *c.SessionToken,
		ProviderName:    "CachingSessionTokenProvider",
	}

	p.Logger.Debugf("ASSUME ROLE CREDENTIALS: %+v", v)
	return v, nil
}
