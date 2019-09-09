package ssm

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
)

type SessionHandler struct {
	client ssmiface.SSMAPI
	log    aws.Logger
}

func NewSsmHandler(c client.ConfigProvider) *SessionHandler {
	return &SessionHandler{client: ssm.New(c)}
}

func (h *SessionHandler) WithLogger(l aws.Logger) *SessionHandler {
	h.log = l
	return h
}

func (h *SessionHandler) StartSession(target string) error {
	in := ssm.StartSessionInput{Target: aws.String(target)}
	return h.send(&in)
}

func (h *SessionHandler) ForwardPort(target, lp, rp string) error {
	params := make(map[string][]*string)
	params["localPortNumber"] = []*string{aws.String(lp)}
	params["portNumber"] = []*string{aws.String(rp)}

	in := ssm.StartSessionInput{
		DocumentName: aws.String("AWS-StartPortForwardingSession"),
		Target:       aws.String(target),
		Parameters:   params,
	}
	return h.send(&in)
}

func (h *SessionHandler) send(input *ssm.StartSessionInput) error {
	out, err := h.client.StartSession(input)
	if err != nil {
		return err
	}

	// todo output is a websocket URL which we need to connect to in order to dtn
	h.log.Log(out)
	return nil
}
