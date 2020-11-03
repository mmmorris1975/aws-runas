package cli

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/awstesting/mock"
	"github.com/mmmorris1975/aws-runas/credentials"
	"testing"
	"time"
)

func TestHelpers_installSignalHandler(t *testing.T) {
	installSignalHandler()
}

func TestHelpers_printCredIdentity(t *testing.T) {
	creds := credentials.Credentials{
		AccessKeyId:     "AKIAmock",
		SecretAccessKey: "mockSecret",
	}

	s := mock.Session
	s.Config.Region = aws.String("us-east-2")
	if err := printCredIdentity(s, &creds); err != nil {
		t.Error(err)
	}
}

func TestHelpers_printCredExpiration(t *testing.T) {
	//if _, err := io.Copy(os.Stdout, os.Stderr); err != nil {
	//	t.Error(err)
	//	return
	//}

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
