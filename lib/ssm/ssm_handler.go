package ssm

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"os"
	"os/exec"
)

type SessionHandler struct {
	client   ssmiface.SSMAPI
	log      aws.Logger
	region   string
	endpoint string
}

func NewSsmHandler(c client.ConfigProvider) *SessionHandler {
	s := ssm.New(c)
	r := s.SigningRegion
	ep := s.Endpoint
	return &SessionHandler{client: s, region: r, endpoint: ep}
}

func (h *SessionHandler) WithLogger(l aws.Logger) *SessionHandler {
	h.log = l
	return h
}

func (h *SessionHandler) StartSession(target string) error {
	in := ssm.StartSessionInput{Target: aws.String(target)}

	c, err := h.cmd(&in)
	if err != nil {
		return err
	}
	return c.Run()
}

func (h *SessionHandler) ForwardPort(target, lp, rp string) error {
	params := map[string][]*string{
		"localPortNumber": {aws.String(lp)},
		"portNumber":      {aws.String(rp)},
	}

	in := ssm.StartSessionInput{
		DocumentName: aws.String("AWS-StartPortForwardingSession"),
		Target:       aws.String(target),
		Parameters:   params,
	}

	c, err := h.cmd(&in)
	if err != nil {
		return err
	}
	return c.Run()
}

func (h *SessionHandler) cmd(input *ssm.StartSessionInput) (*exec.Cmd, error) {
	out, err := h.client.StartSession(input)
	if err != nil {
		return nil, err
	}

	outJ, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}

	inJ, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	c := exec.Command("session-manager-plugin", string(outJ), h.region, "StartSession", "", string(inJ), h.endpoint)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	return c, nil
}
