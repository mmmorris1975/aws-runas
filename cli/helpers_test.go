package cli

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/logging"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/simple-logger/logger"
	"strings"
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

func Test_logFunc(t *testing.T) {
	sb := new(strings.Builder)
	log = logger.NewLogger(sb, "", 0)

	t.Run("debug", func(t *testing.T) {
		log.SetLevel(logger.DEBUG)
		logFunc(logging.Debug, "%s", t.Name())

		if sb.String() != fmt.Sprintf("DEBUG %s\n", t.Name()) {
			t.Error("data mismatch")
		}
		sb.Reset()
	})

	t.Run("warn", func(t *testing.T) {
		log.SetLevel(logger.WARN)
		logFunc(logging.Warn, "%s", t.Name())

		if sb.String() != fmt.Sprintf("WARN %s\n", t.Name()) {
			t.Error("data mismatch")
		}
		sb.Reset()
	})

	t.Run("other", func(t *testing.T) {
		log.SetLevel(logger.DEBUG)
		logFunc("other", "%s", t.Name())

		if sb.String() != fmt.Sprintf("INFO %s\n", t.Name()) {
			t.Error("data mismatch")
		}
		sb.Reset()
	})
}

type mockStsApi bool

func (m *mockStsApi) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
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
