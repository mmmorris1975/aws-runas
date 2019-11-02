package metadata

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/mmmorris1975/simple-logger/logger"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	// EcsCredentialsPath is the URL path used to retrieve the credentials
	EcsCredentialsPath = "/credentials"
)

// EcsMetadataInput contains the options available for customizing the behavior of the ECS Metadata Service
type EcsMetadataInput struct {
	// Credentials is the AWS credentials.Credentials object used to fetch the credentials.  This allows us to have
	// the service return role credentials, or session credentials (in case the caller's code does its own role management)
	Credentials *credentials.Credentials
	// Logger is the logging object to configure for the service.  If not provided, a standard logger is configured.
	Logger *logger.Logger
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
	if log == nil {
		log = logger.StdLogger
	}

	s := new(EcsMetadataService)

	// The SDK seems to only support listening on "localhost" and 127.0.0.1, not the ::1 IPv6 loopback, try not to be clever
	l, err := net.Listen("tcp", "127.0.0.1:0")
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
