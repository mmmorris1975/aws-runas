package credentials

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/mmmorris1975/aws-runas/lib/cache"
	"os"
	"testing"
	"time"
)

type mockStsClient struct {
	stsiface.STSAPI
}

func (c *mockStsClient) GetSessionToken(in *sts.GetSessionTokenInput) (*sts.GetSessionTokenOutput, error) {
	if err := validateMfa(in.SerialNumber, in.TokenCode); err != nil {
		return nil, err
	}
	return &sts.GetSessionTokenOutput{Credentials: buildCreds(*in.DurationSeconds)}, nil
}

func (c *mockStsClient) AssumeRole(in *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	if err := validateMfa(in.SerialNumber, in.TokenCode); err != nil {
		return nil, err
	}
	return &sts.AssumeRoleOutput{Credentials: buildCreds(*in.DurationSeconds)}, nil
}

func (c *mockStsClient) GetCallerIdentity(in *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	return new(sts.GetCallerIdentityOutput).
		SetAccount("123456789012").
		SetArn("arn:aws:iam::123456789012:user/bob").
		SetUserId("AIDAB0B"), nil
}

func validateMfa(ser *string, code *string) error {
	if ser != nil && len(*ser) > 0 {
		if code != nil {
			if len(*code) < 1 {
				return fmt.Errorf("missing MFA Token Code")
			} else if *code != "123456" {
				return fmt.Errorf("invalid token code")
			}
		}
	}
	return nil
}

func buildCreds(duration int64) *sts.Credentials {
	exp := time.Now().Add(time.Duration(duration) * time.Second)
	t := time.Now().UnixNano()
	return &sts.Credentials{
		AccessKeyId:     aws.String(fmt.Sprintf("ASIAM0CK%d", t)),
		SecretAccessKey: aws.String(fmt.Sprintf("s3crEtK3Y%d", t)),
		SessionToken:    aws.String(fmt.Sprintf("MyS3ss10N%d", t)),
		Expiration:      &exp,
	}
}

type mockCredentialCache struct {
	*cache.CacheableCredentials
}

func (c *mockCredentialCache) Fetch() (*cache.CacheableCredentials, error) {
	if c.CacheableCredentials == nil {
		return new(cache.CacheableCredentials), nil
	}
	return c.CacheableCredentials, nil
}

func (c *mockCredentialCache) Store(creds *cache.CacheableCredentials) error {
	c.CacheableCredentials = creds
	return nil
}

func TestNewSessionCredentials(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		s := session.Must(session.NewSession())
		c := NewSessionCredentials(s)

		if !c.IsExpired() {
			t.Error("expected expired credentials")
			return
		}
	})

	t.Run("nil config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewSessionCredentials with nil config")
			}
		}()
		NewSessionCredentials(nil)
	})

	t.Run("options", func(t *testing.T) {
		s := session.Must(session.NewSession())
		c := NewSessionCredentials(s, func(p *SessionTokenProvider) {
			p.Duration = SessionTokenMaxDuration
			p.ExpiryWindow = 1 * time.Microsecond
		})

		if !c.IsExpired() {
			t.Error("expected expired credentials")
			return
		}
	})
}

func TestSessionTokenProvider_Retrieve(t *testing.T) {
	t.Run("no mfa", func(t *testing.T) {
		p := &SessionTokenProvider{
			client: new(mockStsClient),
		}

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != SessionTokenProviderName {
			t.Error("provider name mismatch")
		}
	})

	t.Run("large duration", func(t *testing.T) {
		p := &SessionTokenProvider{
			client:   new(mockStsClient),
			Duration: SessionTokenMaxDuration + 1*time.Hour,
		}

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != SessionTokenProviderName {
			t.Error("provider name mismatch")
		}
	})

	t.Run("mfa", func(t *testing.T) {
		p := &SessionTokenProvider{
			client:       new(mockStsClient),
			SerialNumber: "MFAtime",
		}

		t.Run("no token", func(t *testing.T) {
			_, err := p.Retrieve()
			if err == nil {
				t.Error("did not receive expected error")
			}
		})

		t.Run("bad token", func(t *testing.T) {
			p.TokenCode = "abcdef"
			_, err := p.Retrieve()
			if err == nil {
				t.Error("did not receive expected error")
			}
		})

		t.Run("token func", func(t *testing.T) {
			p.TokenCode = ""
			p.TokenProvider = func() (string, error) {
				return "123456", nil
			}

			c, err := p.Retrieve()
			if err != nil {
				t.Error(err)
				return
			}

			if c.ProviderName != SessionTokenProviderName {
				t.Error("provider name mismatch")
			}
		})

		t.Run("token func error", func(t *testing.T) {
			p.SetExpiration(time.Now(), 0)
			p.TokenCode = ""
			p.TokenProvider = func() (string, error) {
				return "", fmt.Errorf("an error")
			}

			_, err := p.Retrieve()
			if err == nil {
				t.Error("did not receive expected error")
				return
			}
		})
	})

	t.Run("cache", func(t *testing.T) {
		cc := new(mockCredentialCache)

		t.Run("empty", func(t *testing.T) {
			p := &SessionTokenProvider{
				client:       new(mockStsClient),
				Duration:     SessionTokenMinDuration,
				ExpiryWindow: 1 * time.Minute,
				Cache:        cc,
			}

			c, err := p.Retrieve()
			if err != nil {
				t.Error(err)
				return
			}

			if c.ProviderName != SessionTokenProviderName {
				t.Error("provider name mismatch")
			}

			cc, err := p.Cache.Fetch()
			if err != nil {
				t.Error(err)
				return
			}

			if cc.AccessKeyID != c.AccessKeyID {
				t.Error("access key mismatch")
			}

			if cc.SecretAccessKey != c.SecretAccessKey {
				t.Error("secret key mismatch")
			}
		})

		t.Run("expired", func(t *testing.T) {
			cc.CacheableCredentials.Expiration = 1
			oldAK := cc.AccessKeyID
			oldSK := cc.SecretAccessKey

			p := &SessionTokenProvider{
				client:       new(mockStsClient),
				Duration:     SessionTokenMinDuration,
				ExpiryWindow: 1 * time.Minute,
				Cache:        cc,
			}

			c, err := p.Retrieve()
			if err != nil {
				t.Error(err)
				return
			}

			if c.ProviderName != SessionTokenProviderName {
				t.Error("provider name mismatch")
			}

			if oldAK == c.AccessKeyID {
				t.Error("access keys matched")
			}

			if oldSK == c.SecretAccessKey {
				t.Error("secret key matched")
			}
		})

		t.Run("valid", func(t *testing.T) {
			cc.CacheableCredentials = &cache.CacheableCredentials{
				Value: credentials.Value{
					AccessKeyID:     "mock",
					SecretAccessKey: "mock",
					SessionToken:    "mock",
					ProviderName:    SessionTokenProviderName,
				},
				Expiration: time.Now().Add(1 * time.Hour).Unix(),
			}

			p := &SessionTokenProvider{
				client:       new(mockStsClient),
				Duration:     SessionTokenMinDuration,
				ExpiryWindow: 1 * time.Minute,
				Cache:        cc,
			}

			c, err := p.Retrieve()
			if err != nil {
				t.Error(err)
				return
			}

			if c.ProviderName != SessionTokenProviderName {
				t.Error("provider name mismatch")
			}

			if c.AccessKeyID != "mock" {
				t.Error("access keys mismatch")
			}

			if c.SecretAccessKey != "mock" {
				t.Error("secret key mismatch")
			}
		})
	})
}

func TestSessionTokenProvider_WithLogger(t *testing.T) {
	p := new(SessionTokenProvider).WithLogger(aws.NewDefaultLogger())
	if p.log == nil {
		t.Error("unexpected nil logger")
	}
}

func ExampleSessionDebugNilCfg() {
	p := new(SessionTokenProvider)
	p.debug("test")
	// Output:
	//
}

func ExampleSessionDebugNoLog() {
	p := new(SessionTokenProvider)
	p.cfg = new(aws.Config).WithLogLevel(aws.LogDebug)
	p.debug("test")
	// Output:
	//
}

func ExampleSessionDebugLogLevelOff() {
	p := new(SessionTokenProvider)
	p.cfg = new(aws.Config)
	p.log = aws.NewDefaultLogger()
	p.debug("test")
	// Output:
	//
}

func ExampleSessionDebugLogLevelDebug() {
	p := new(SessionTokenProvider)
	p.cfg = new(aws.Config).WithLogLevel(aws.LogDebug)
	p.log = aws.LoggerFunc(func(v ...interface{}) { fmt.Fprintln(os.Stdout, v...) })
	p.debug("test")
	// Output:
	// test
}
