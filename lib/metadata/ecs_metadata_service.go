package metadata

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/mmmorris1975/simple-logger/logger"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	ecsCredentialsPath = "/credentials"
)

// EcsMetadataInput contains the options available for customizing the behavior of the ECS Metadata Service
type EcsMetadataInput struct {
	// Credentials is the AWS credentials.Credentials object used to fetch the credentials.  This allows us to have
	// the service return role credentials, or session credentials (in case the caller's code does its own role management)
	Credentials *credentials.Credentials
	// Logger is the logging object to configure for the service.  If not provided, a standard logger is configured.
	Logger *logger.Logger
	// Port is the port the service will listen on, default is a randomly chosen port.
	Port int16
}

// ecsMetadataService is the object encapsulating the details of the service
type ecsMetadataService struct {
	// Url is the fully-formed URL to use for retrieving credentials from the service
	Url  *url.URL
	lsnr net.Listener
}

// NewEcsMetadataService creates a new ecsMetadataService object using the provided EcsMetadataInput options.
func NewEcsMetadataService(opts *EcsMetadataInput) (*ecsMetadataService, error) {
	cred = opts.Credentials
	log = logger.StdLogger
	if opts.Logger != nil {
		log = opts.Logger
	}

	// The SDK seems to only support listening on "localhost" and 127.0.0.1, not the ::1 IPv6 loopback, try not to be clever
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(opts.Port))))
	if err != nil {
		if _, ok := err.(*net.OpError); ok {
			// listen errors are OS-specific, so we can't scrape the message with any consistency
			// If opts.Port > 0, retry with port set to zero
			if opts.Port > 0 {
				log.Warnf("Error trying to listen with port %d, retrying with random port", opts.Port)
				l, err = net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					return nil, err
				}
			}
		} else {
			return nil, err
		}
	}

	u, _ := url.Parse(fmt.Sprintf("http://%s%s", l.Addr(), ecsCredentialsPath))

	return &ecsMetadataService{Url: u, lsnr: l}, nil
}

// Run starts the HTTP server used to fetch credentials.  The HTTP server will listen on the loopback address on a
// randomly chosen port.
func (s *ecsMetadataService) Run() {
	http.HandleFunc(ecsCredentialsPath, ecsHandler)
	if err := http.Serve(s.lsnr, nil); err != nil && log != nil {
		log.Error(err)
	}
}

func ecsHandler(w http.ResponseWriter, _ *http.Request) {
	var rc = http.StatusOK

	v, err := cred.Get()
	if err != nil {
		rc = http.StatusInternalServerError
		j, err := json.Marshal(&ecsCredentialError{Code: rc, Message: err.Error()})
		if err != nil && log != nil {
			log.Warnf("error converting error message to json: %v", err)
		}

		http.Error(w, string(j), rc)
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

	if log != nil {
		log.Debugf("ECS endpoint credentials: %+v", c)
	}

	j, err := json.Marshal(&c)
	if err != nil && log != nil {
		log.Warnf("error converting credentials to json: %v", err)
	}

	w.WriteHeader(rc)
	_, _ = w.Write(j)
}

type ecsCredentialError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ecsCredentials struct {
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      string
}
