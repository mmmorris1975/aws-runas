package credentials

import (
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"time"
)

// stsMock provides a mock STS client used for testing.
type stsMock struct {
	stsiface.STSAPI
}

// GetSessionTokenWithContext implements the AWS API for getting Session Token credentials for testing.
func (m *stsMock) GetSessionTokenWithContext(_ aws.Context, in *sts.GetSessionTokenInput, _ ...request.Option) (*sts.GetSessionTokenOutput, error) {
	d, err := validateDuration(in.DurationSeconds, 900*time.Second, 36*time.Hour, 12*time.Hour)
	if err != nil {
		return nil, err
	}

	if err = validateMfa(in.SerialNumber, in.TokenCode); err != nil {
		return nil, err
	}

	return new(sts.GetSessionTokenOutput).SetCredentials(buildCredentials(d)), nil
}

// AssumeRoleWithContext implements the AWS API for getting Assume Role credentials for testing.
func (m *stsMock) AssumeRoleWithContext(_ aws.Context, in *sts.AssumeRoleInput, _ ...request.Option) (*sts.AssumeRoleOutput, error) {
	d, err := validateDuration(in.DurationSeconds, 900*time.Second, 36*time.Hour, 12*time.Hour)
	if err != nil {
		return nil, err
	}

	if err = validateMfa(in.SerialNumber, in.TokenCode); err != nil {
		return nil, err
	}

	if err = validateRoleArn(in.RoleArn); err != nil {
		return nil, err
	}

	if err = validateRoleSessionName(in.RoleSessionName); err != nil {
		return nil, err
	}

	return new(sts.AssumeRoleOutput).SetCredentials(buildCredentials(d)), nil
}

// AssumeRoleWithSAMLWithContext implements the AWS API for getting role credentials using SAML for testing.
func (m *stsMock) AssumeRoleWithSAMLWithContext(_ aws.Context, in *sts.AssumeRoleWithSAMLInput, _ ...request.Option) (*sts.AssumeRoleWithSAMLOutput, error) {
	d, err := validateDuration(in.DurationSeconds, 900*time.Second, 36*time.Hour, 12*time.Hour)
	if err != nil {
		return nil, err
	}

	if err = validateRoleArn(in.RoleArn); err != nil {
		return nil, err
	}

	if err = validatePrincipalArn(in.PrincipalArn); err != nil {
		return nil, err
	}

	if err = validateSamlAssertion(in.SAMLAssertion); err != nil {
		return nil, err
	}

	return new(sts.AssumeRoleWithSAMLOutput).SetCredentials(buildCredentials(d)), nil
}

// AssumeRoleWithWebIdentityWithContext implements the AWS API for getting role credentials using Oauth2/OIDC for testing.
func (m *stsMock) AssumeRoleWithWebIdentityWithContext(_ aws.Context, in *sts.AssumeRoleWithWebIdentityInput, _ ...request.Option) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	d, err := validateDuration(in.DurationSeconds, 900*time.Second, 36*time.Hour, 12*time.Hour)
	if err != nil {
		return nil, err
	}

	if err = validateRoleArn(in.RoleArn); err != nil {
		return nil, err
	}

	if err = validateRoleSessionName(in.RoleSessionName); err != nil {
		return nil, err
	}

	if err = validateWebIdentityToken(in.WebIdentityToken); err != nil {
		return nil, err
	}

	return new(sts.AssumeRoleWithWebIdentityOutput).SetCredentials(buildCredentials(d)), nil
}

// if duration != nil (default), must be in acceptable range.
func validateDuration(d *int64, min, max, def time.Duration) (time.Duration, error) {
	if d != nil {
		t := time.Duration(*d) * time.Second
		if t < min || t > max {
			return time.Duration(0), errors.New("InvalidParameter")
		}
		return t, nil
	}
	return def, nil
}

func validateMfa(serial, code *string) error {
	if serial != nil && len(*serial) > 0 {
		if code != nil && *code == "123456" {
			return nil
		}
		return errors.New("mfa required")
	}

	// mfa not required
	return nil
}

func validateRoleArn(role *string) error {
	if role != nil && len(*role) > 2 {
		return nil
	}
	return errors.New("invalid role arn")
}

func validateRoleSessionName(name *string) error {
	if name != nil && len(*name) > 2 {
		return nil
	}
	return errors.New("invalid role session name")
}

func validatePrincipalArn(p *string) error {
	if p != nil && len(*p) > 20 {
		return nil
	}
	return errors.New("invalid principal arn")
}

func validateSamlAssertion(a *string) error {
	if a != nil && len(*a) > 4 {
		return nil
	}
	return errors.New("invalid saml assertion")
}

func validateWebIdentityToken(t *string) error {
	if t != nil && len(*t) > 4 {
		return nil
	}
	return errors.New("invalid web identity token")
}

func buildCredentials(d time.Duration) *sts.Credentials {
	t := time.Now().Unix()

	return &sts.Credentials{
		AccessKeyId:     aws.String(fmt.Sprintf("AKIAM0CK%d", t)),
		Expiration:      aws.Time(time.Now().Add(d)),
		SecretAccessKey: aws.String(fmt.Sprintf("s3cR3TkEy%d", t)),
		SessionToken:    aws.String(fmt.Sprintf("t0k3N%d", t)),
	}
}

type memCredCache struct {
	creds *Credentials
}

func (c *memCredCache) Load() *Credentials {
	if c.creds == nil {
		c.creds = new(Credentials)
	}
	return c.creds
}

func (c *memCredCache) Store(creds *Credentials) error {
	c.creds = creds
	return nil
}

func (c *memCredCache) Clear() error {
	c.creds = nil
	return nil
}
