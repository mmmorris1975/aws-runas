package cli

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/mmmorris1975/aws-runas/credentials"
	"testing"
	"time"
)

func TestHelpers_installSignalHandler(t *testing.T) {
	installSignalHandler()
}

func TestHelpers_printCredIdentity(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		if err := printCredIdentity(new(mockStsApi)); err != nil {
			t.Error(err)
		}
	})

	t.Run("bad", func(t *testing.T) {
		var api mockStsApi = true
		if err := printCredIdentity(&api); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestHelpers_printCredExpiration(t *testing.T) {
	// if _, err := io.Copy(os.Stdout, os.Stderr); err != nil {
	//	t.Error(err)
	//	return
	// }

	t.Run("never", func(t *testing.T) {
		creds := &credentials.Credentials{Expiration: time.Time{}}
		printCredExpiration(creds)
	})

	t.Run("expired", func(t *testing.T) {
		creds := &credentials.Credentials{Expiration: time.Time{}.Add(1 * time.Nanosecond)}
		printCredExpiration(creds)
	})

	t.Run("valid", func(t *testing.T) {
		creds := &credentials.Credentials{Expiration: time.Now().Add(999999 * time.Hour)}
		printCredExpiration(creds)
	})
}

func TestHelpers_refreshCreds(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		refreshCreds(new(mockAwsClient))
	})

	t.Run("bad", func(t *testing.T) {
		c := mockAwsClient(true)
		refreshCreds(&c)
	})
}

type mockStsApi bool

func (m *mockStsApi) GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, opts ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if *m {
		return nil, errors.New("failed")
	}

	out := &sts.GetCallerIdentityOutput{
		Account: aws.String("mockAccount"),
		Arn:     aws.String("arn:aws:iam::0123456789:user/Mock"),
		UserId:  aws.String("mockUser"),
	}

	return out, nil
}
