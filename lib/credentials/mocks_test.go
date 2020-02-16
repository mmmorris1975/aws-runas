package credentials

import (
	"aws-runas/lib/cache"
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"strings"
	"testing"
	"time"
)

type stsMock struct {
	stsiface.STSAPI
}

func (m *stsMock) GetSessionToken(in *sts.GetSessionTokenInput) (*sts.GetSessionTokenOutput, error) {
	if err := m.validateDuration(in.DurationSeconds, SessionTokenMaxDuration); err != nil {
		return nil, err
	}

	if err := m.validateMfa(in.SerialNumber, in.TokenCode); err != nil {
		return nil, err
	}

	out := new(sts.GetSessionTokenOutput).SetCredentials(m.buildCreds(in.DurationSeconds))
	return out, nil
}

func (m *stsMock) AssumeRole(in *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	if err := m.validateDuration(in.DurationSeconds, AssumeRoleMaxDuration); err != nil {
		return nil, err
	}

	if err := m.validateRoleArn(in.RoleArn); err != nil {
		return nil, err
	}

	if err := m.validateMfa(in.SerialNumber, in.TokenCode); err != nil {
		return nil, err
	}

	if in.ExternalId != nil && len(*in.ExternalId) > 0 {
		if *in.ExternalId != "ItsAllGood" {
			return nil, fmt.Errorf("invalid ExternalId")
		}
	}

	out := new(sts.AssumeRoleOutput).SetCredentials(m.buildCreds(in.DurationSeconds))
	return out, nil
}

func (m *stsMock) AssumeRoleWithSAML(in *sts.AssumeRoleWithSAMLInput) (*sts.AssumeRoleWithSAMLOutput, error) {
	if err := m.validateDuration(in.DurationSeconds, AssumeRoleMaxDuration); err != nil {
		return nil, err
	}

	if err := m.validateSAMLAssertion(in.SAMLAssertion, in.RoleArn, in.PrincipalArn); err != nil {
		return nil, err
	}

	out := new(sts.AssumeRoleWithSAMLOutput).SetCredentials(m.buildCreds(in.DurationSeconds))
	return out, nil
}

// The role and principal ARNs must be well-formed, and the SAMLAssertion data must contain
// the string RoleArn,PrincipalArn (we're not actually validating that this is correct SAML XML)
func (m *stsMock) validateSAMLAssertion(saml *string, role *string, p *string) error {
	if err := m.validateRoleArn(role); err != nil {
		return err
	}

	if err := m.validatePrincipalArn(p); err != nil {
		return err
	}

	decodedSaml, err := base64.StdEncoding.DecodeString(*saml)
	if err != nil {
		return err
	}

	if saml != nil && len(*saml) > 0 {
		if !strings.Contains(string(decodedSaml), fmt.Sprintf("%s,%s", *role, *p)) {
			return fmt.Errorf("role not authorized")
		}

		// all good
		return nil
	}
	return fmt.Errorf("invalid SAMLAssertion document")
}

// Must be a well-formed ARN for the IAM service with a resource name starting with "saml-provider/"
func (m *stsMock) validatePrincipalArn(p *string) error {
	if p != nil && len(*p) > 0 {
		a, err := arn.Parse(*p)
		if err != nil {
			return err
		}

		if a.Service != "iam" || !strings.HasPrefix(a.Resource, "saml-provider/") {
			return fmt.Errorf("not an IAM SAML provider ARN")
		}

		// all good
		return nil
	}
	return fmt.Errorf("invalid principal arn")
}

// Must be a well-formed ARN for the IAM service with a resource name starting with "role/"
func (m *stsMock) validateRoleArn(role *string) error {
	if role != nil && len(*role) > 0 {
		a, err := arn.Parse(*role)
		if err != nil {
			return err
		}

		if a.Service != "iam" || !strings.HasPrefix(a.Resource, "role/") {
			return fmt.Errorf("not an IAM role ARN")
		}

		// all good
		return nil
	}
	return fmt.Errorf("invalid role arn")
}

// If we have a non-nil, non-empty serial, check that the provided code is "123456", otherwise fail
func (m *stsMock) validateMfa(serial *string, code *string) error {
	if serial != nil && len(*serial) > 0 {
		if code != nil {
			if len(*code) > 0 {
				if *code == "123456" {
					return nil
				}
				return fmt.Errorf("invalid MFA code")
			}

			return fmt.Errorf("missing MFA code")
		}

		return fmt.Errorf("missing MFA code")
	}
	return nil
}

// STS token calls all have a minimum duration of 15 minutes, but varying maximum times.  For this validation, just
// check that the supplied duration isn't nil, is at least the common minimum value, and isn't higher than max
func (m *stsMock) validateDuration(s *int64, max time.Duration) error {
	if s == nil {
		return fmt.Errorf("nil duration")
	}

	d := time.Duration(*s) * time.Second
	if d < AssumeRoleMinDuration || d > max {
		return fmt.Errorf("invalid duration")
	}
	return nil
}

func (m *stsMock) buildCreds(duration *int64) *sts.Credentials {
	exp := time.Now().Add(time.Duration(*duration) * time.Second)
	t := time.Now().UnixNano()
	return &sts.Credentials{
		AccessKeyId:     aws.String(fmt.Sprintf("ASIAM0CK%d", t)),
		SecretAccessKey: aws.String(fmt.Sprintf("s3crEtK3Y%d", t)),
		SessionToken:    aws.String(fmt.Sprintf("MyS3ss10N%d", t)),
		Expiration:      &exp,
	}
}

type credentialCacheMock struct {
	*cache.CacheableCredentials
}

func (c *credentialCacheMock) Load() (*cache.CacheableCredentials, error) {
	if c.CacheableCredentials == nil {
		return &cache.CacheableCredentials{Expiration: aws.Time(time.Now())}, nil
	}
	return c.CacheableCredentials, nil
}

func (c *credentialCacheMock) Store(creds *cache.CacheableCredentials) error {
	c.CacheableCredentials = creds
	return nil
}

// Testable function to ensure we're conforming to the documented test file format
func TestNoOp(t *testing.T) {
	t.SkipNow()
}
