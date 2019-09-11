package ssm

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	logger "github.com/mmmorris1975/simple-logger"
	"testing"
)

type mockSsmClient struct {
	ssmiface.SSMAPI
}

func (c *mockSsmClient) StartSession(input *ssm.StartSessionInput) (*ssm.StartSessionOutput, error) {
	if input.Target == nil || len(*input.Target) < 1 {
		return nil, fmt.Errorf(ssm.ErrCodeInvalidTarget)
	}

	if input.DocumentName != nil && *input.DocumentName != "AWS-StartPortForwardingSession" && *input.DocumentName != "SSM-SessionManagerRunShell" {
		return nil, fmt.Errorf(ssm.ErrCodeInvalidDocument)
	}

	o := new(ssm.StartSessionOutput)
	o.StreamUrl = aws.String("wss://aws.example.com/path/to/ssmmessages")
	o.SessionId = aws.String("ASIDSSMMOCKSESSION")
	o.TokenValue = aws.String("token-TokenValue")

	return o, nil
}

func TestNewSsmHandler(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		h := NewSsmHandler(session.Must(session.NewSession(new(aws.Config).WithRegion("us-east-1"))))
		if h.client == nil {
			t.Error("nil client")
		}

		if len(h.region) < 1 {
			t.Error("empty region")
		}
	})

	t.Run("nil config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Error("Did not receive expected panic calling NewSessionCredentials with nil config")
			}
		}()
		NewSsmHandler(nil)
	})

	t.Run("with logger", func(t *testing.T) {
		h := NewSsmHandler(session.Must(session.NewSession())).WithLogger(logger.StdLogger)
		if h == nil {
			t.Error("nil client")
			return
		}

		if h.log == nil {
			t.Error("nil logger")
		}
	})
}

func TestCmd(t *testing.T) {
	h := &SessionHandler{client: new(mockSsmClient), region: "us-east-1"}

	t.Run("empty target", func(t *testing.T) {
		if _, err := h.cmd(new(ssm.StartSessionInput)); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("invalid doc", func(t *testing.T) {
		if _, err := h.cmd(&ssm.StartSessionInput{Target: aws.String("x"), DocumentName: aws.String("x")}); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("cmd", func(t *testing.T) {
		in := &ssm.StartSessionInput{Target: aws.String("i-deadbeef")}
		if c, err := h.cmd(in); err != nil {
			t.Error(err)
			return
		} else {
			if len(c.Args) < 1 || c.Args[0] != "session-manager-plugin" || c.Args[3] != "StartSession" {
				t.Errorf("bad command: %v", c.Args)
				return
			}
		}
	})
}
