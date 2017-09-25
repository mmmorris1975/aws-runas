package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"os/user"
	"path/filepath"
	"time"
)

type CachingSessionTokenProvider struct {
	CredentialsCacherProvider
	Profile   string
	Duration  time.Duration
	MfaSerial string
}

func (p *CachingSessionTokenProvider) CacheFile() string {
	cacheDir = filepath.Dir(defaults.SharedCredentialsFilename())
	return filepath.Join(cacheDir, fmt.Sprintf(".aws_session_token_%s", p.Profile))
}

// Satisfies credentials.Provider
func (p *CachingSessionTokenProvider) Retrieve() (credentials.Value, error) {
	p.CredentialsCacherProvider.CacheFilename = p.CacheFile()
	creds, _ := p.CredentialsCacherProvider.Retrieve() // TODO let errors fall through?

	if p.IsExpired() {
		dur_secs := int64(p.Duration.Seconds())
		input := sts.GetSessionTokenInput{DurationSeconds: &dur_secs}

		if len(p.MfaSerial) > 0 {
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
		p.CredentialsCacherProvider.Store(&c)
		creds, _ = p.CredentialsCacherProvider.Retrieve()
	}

	return creds, nil
}

// Satisfies credentials.Provider
func (p *CachingSessionTokenProvider) IsExpired() bool {
	expired := true
	expired = p.CredentialsCacherProvider.IsExpired()

	return expired
}

func (p *CachingSessionTokenProvider) AssumeRole(profile_cfg *AWSProfile) (*sts.Credentials, error) {
	username := "__"
	user, err := user.Current()
	if err == nil {
		username = user.Username
	}

	sesName := aws.String(fmt.Sprintf("AWS-RUNAS-%s-%d", username, time.Now().Unix()))
	input := sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(int64(3600)),
		RoleArn:         aws.String(profile_cfg.RoleArn),
		RoleSessionName: sesName,
	}

	creds, err := p.Retrieve()
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return res.Credentials, nil
}
