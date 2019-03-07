package credentials

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/mmmorris1975/aws-runas/lib/cache"
	"os"
	"testing"
	"time"
)

func TestNewAssumeRoleCredentials(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		s := session.Must(session.NewSession())
		c := NewAssumeRoleCredentials(s, "")

		if !c.IsExpired() {
			t.Error("expected expired credentials")
			return
		}
	})

	t.Run("nil_config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewSessionCredentials with nil config")
			}
		}()
		NewAssumeRoleCredentials(nil, "")
	})

	t.Run("options", func(t *testing.T) {
		s := session.Must(session.NewSession())
		c := NewAssumeRoleCredentials(s, "myRole", func(p *AssumeRoleProvider) {
			p.Duration = SessionTokenMaxDuration
			p.ExpiryWindow = 1 * time.Microsecond
		})

		if !c.IsExpired() {
			t.Error("expected expired credentials")
			return
		}
	})
}

func TestAssumeRoleProvider_Retrieve(t *testing.T) {
	t.Run("no mfa", func(t *testing.T) {
		p := &AssumeRoleProvider{
			client:     new(mockStsClient),
			ExternalID: "extID",
		}

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != AssumeRoleProviderName {
			t.Error("provider name mismatch")
		}
	})

	t.Run("large duration", func(t *testing.T) {
		p := &AssumeRoleProvider{
			client:   new(mockStsClient),
			Duration: AssumeRoleMaxDuration + 1*time.Hour,
		}

		c, err := p.Retrieve()
		if err != nil {
			t.Error(err)
			return
		}

		if c.ProviderName != AssumeRoleProviderName {
			t.Error("provider name mismatch")
		}
	})

	t.Run("mfa", func(t *testing.T) {
		p := &AssumeRoleProvider{
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

			if c.ProviderName != AssumeRoleProviderName {
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
			p := &AssumeRoleProvider{
				client:       new(mockStsClient),
				Duration:     AssumeRoleMinDuration,
				ExpiryWindow: 1 * time.Minute,
				Cache:        cc,
			}

			c, err := p.Retrieve()
			if err != nil {
				t.Error(err)
				return
			}

			if c.ProviderName != AssumeRoleProviderName {
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

			p := &AssumeRoleProvider{
				client:       new(mockStsClient),
				Duration:     AssumeRoleMinDuration,
				ExpiryWindow: 1 * time.Minute,
				Cache:        cc,
			}

			c, err := p.Retrieve()
			if err != nil {
				t.Error(err)
				return
			}

			if c.ProviderName != AssumeRoleProviderName {
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
					ProviderName:    AssumeRoleProviderName,
				},
				Expiration: time.Now().Add(1 * time.Hour).Unix(),
			}

			p := &SessionTokenProvider{
				client:       new(mockStsClient),
				Duration:     AssumeRoleMinDuration,
				ExpiryWindow: 1 * time.Minute,
				Cache:        cc,
			}

			c, err := p.Retrieve()
			if err != nil {
				t.Error(err)
				return
			}

			if c.ProviderName != AssumeRoleProviderName {
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

func TestAssumeRoleProvider_WithLogger(t *testing.T) {
	p := new(AssumeRoleProvider).WithLogger(aws.NewDefaultLogger())
	if p.log == nil {
		t.Error("unexpected nil logger")
	}
}

func Example_StdinTokenProvider() {
	StdinTokenProvider()
	// Output:
	// Enter MFA Code:
}

func Example_RoleDebugNilCfg() {
	p := new(AssumeRoleProvider)
	p.debug("test")
	// Output:
	//
}

func Example_RoleDebugNoLog() {
	p := new(AssumeRoleProvider)
	p.cfg = new(aws.Config).WithLogLevel(aws.LogDebug)
	p.debug("test")
	// Output:
	//
}

func Example_RoleDebugLogLevelOff() {
	p := new(AssumeRoleProvider)
	p.cfg = new(aws.Config)
	p.log = aws.NewDefaultLogger()
	p.debug("test")
	// Output:
	//
}

func Example_RoleDebugLogLevelDebug() {
	p := new(AssumeRoleProvider)
	p.cfg = new(aws.Config).WithLogLevel(aws.LogDebug)
	p.log = aws.LoggerFunc(func(v ...interface{}) { fmt.Fprintln(os.Stdout, v...) })
	p.debug("test")
	// Output:
	// test
}
