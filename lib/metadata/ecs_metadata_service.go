package metadata

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials"
	simple_logger "github.com/mmmorris1975/simple-logger"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// EcsCredentialsPath is the URL path used to retrieve the credentials
	EcsCredentialsPath = "/credentials"
)

// EcsMetadataInput contains the options available for customizing the behavior of the ECS Metadata Service
type EcsMetadataInput struct {
	Credentials *credentials.Credentials
	Logger      *simple_logger.Logger
}

// EcsMetadataService is the object encapsulating the details of the service
type EcsMetadataService struct {
	// Url is the fully-formed URL to use for retrieving credentials from the service
	Url  *url.URL
	lsnr net.Listener
}

// NewEcsMetadataService creates a new EcsMetadataService object using the provided EcsMetadataInput options.
func NewEcsMetadataService(opts *EcsMetadataInput) (*EcsMetadataService, error) {
	cred = opts.Credentials
	log = opts.Logger

	s := new(EcsMetadataService)

	l, err := setupListener()
	if err != nil {
		return nil, err
	}
	s.lsnr = l

	u, err := url.Parse(fmt.Sprintf("http://%s%s", l.Addr(), EcsCredentialsPath))
	if err != nil {
		return nil, err
	}
	s.Url = u

	return s, nil
}

// Run starts the HTTP server used to fetch credentials.  The HTTP server will listen on the loopback address on a
// randomly chosen port.
func (s *EcsMetadataService) Run() {
	http.HandleFunc(EcsCredentialsPath, ecsHandler)
	if err := http.Serve(s.lsnr, nil); err != nil {
		log.Error(err)
	}
}

func setupListener() (net.Listener, error) {
	loName, err := discoverLoopback()
	if err != nil {
		return nil, err
	}

	loIface, err := net.InterfaceByName(loName)
	if err != nil {
		return nil, err
	}
	log.Debugf("found loopback interface: %s", loIface.Name)

	loAddrs, err := loIface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, a := range loAddrs {
		if strings.HasPrefix(a.Network(), "ip+net") {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil {
				// Treat as non-fatal, just keep trying until we run out of loopback addresses
				log.Debugf("error parsing interface address '%s': %v", a.String(), err)
				continue
			}

			return net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
		}
	}

	return nil, fmt.Errorf("no suitable loopback interface found")
}

func ecsHandler(w http.ResponseWriter, r *http.Request) {
	var rc = http.StatusOK

	v, err := cred.Get()
	if err != nil {
		rc = http.StatusInternalServerError
		j, err := json.Marshal(&ecsCredentialError{Code: string(rc), Message: err.Error()})
		if err != nil {
			log.Warnf("error converting error message to json: %v", err)
		}

		w.WriteHeader(rc)
		w.Write(j)
		return
	}

	e, err := cred.ExpiresAt()
	if err != nil {
		e = time.Now()
	}

	c := ecsCredentials{
		AccessKeyId:     v.AccessKeyID,
		SecretAccessKey: v.SecretAccessKey,
		Token:           v.SessionToken,
		Expiration:      e.UTC().Format(time.RFC3339),
	}
	log.Debugf("ECS endpoint credentials: %+v", c)

	j, err := json.Marshal(&c)
	if err != nil {
		log.Warnf("error converting credentials to json: %v", err)
	}

	w.WriteHeader(rc)
	w.Write(j)
}

type ecsCredentialError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ecsCredentials struct {
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      string
}
