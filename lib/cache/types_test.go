package cache

import (
	"github.com/aws/aws-sdk-go/aws"
	"testing"
)

func TestCacheableCredentials_Value(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		creds := &CacheableCredentials{
			AccessKeyId:     aws.String("AKIAMOCK"),
			SecretAccessKey: aws.String("secret"),
			SessionToken:    aws.String("token"),
		}

		v := creds.Value("x")
		if v.AccessKeyID != "AKIAMOCK" || v.SecretAccessKey != "secret" || v.SessionToken != "token" || v.ProviderName != "x" {
			t.Error("data mismatch")
		}
	})

	t.Run("all nil", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Error("did not receive expected panic")
			}
		}()

		creds := &CacheableCredentials{
			AccessKeyId:     nil,
			SecretAccessKey: nil,
			SessionToken:    nil,
		}

		creds.Value("y")
	})
}
