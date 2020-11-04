package metadata

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/mmmorris1975/aws-runas/client"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/credentials/helpers"
	"github.com/mmmorris1975/aws-runas/shared"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

const (
	DefaultEcsCredPath = "/credentials"
	DefaultEc2ImdsAddr = "169.254.169.254"

	ec2CredPath   = "/latest/meta-data/iam/security-credentials/"
	authPath      = "/auth"
	profilePath   = "/profile"
	listRolesPath = "/list-roles"
	refreshPath   = "/refresh"
	imdsTokenPath = "/latest/api/token" //nolint:gosec // remove false positive because Token is in the const name
)

var (
	logger shared.Logger = new(shared.DefaultLogger)
)

type Options struct {
	Path        string
	Profile     string
	Logger      shared.Logger
	AwsLogLevel aws.LogLevelType
}

type metadataCredentialService struct {
	options        *Options
	awsClient      client.AwsClient
	awsConfig      *config.AwsConfig
	configResolver config.Resolver
	clientFactory  *client.Factory
	clientOptions  *client.Options
	listener       net.Listener
}

func NewMetadataCredentialService(addr string, opts *Options) (*metadataCredentialService, error) {
	mcs := new(metadataCredentialService)
	mcs.options = opts

	if opts.Logger != nil {
		logger = opts.Logger
	}

	mcs.configResolver = config.DefaultResolver.WithLogger(logger)

	// leave setting of MFA and credential input providers until later (which also means deferring the client factory)
	mcs.clientOptions = client.DefaultOptions
	mcs.clientOptions.Logger = logger
	mcs.clientOptions.AwsLogLevel = opts.AwsLogLevel

	var err error
	mcs.listener, err = configureListener(addr)
	if err != nil {
		return nil, err
	}

	return mcs, nil
}

func (s *metadataCredentialService) Addr() net.Addr {
	return s.listener.Addr()
}

func (s *metadataCredentialService) Run() error {
	// todo set these to web-aware providers
	s.clientOptions.MfaInputProvider = nil
	s.clientOptions.CredentialInputProvider = nil

	s.clientFactory = client.NewClientFactory(s.configResolver, s.clientOptions)

	// todo setup all handlers with logging
	mux := http.NewServeMux()
	// mux.HandleFunc("/", nil)
	mux.HandleFunc(authPath, logHandler(s.authHandler))
	mux.HandleFunc(profilePath, logHandler(s.profileHandler))
	mux.HandleFunc(listRolesPath, logHandler(s.listRolesHandler))
	mux.HandleFunc(refreshPath, logHandler(s.refreshHandler))
	mux.HandleFunc(imdsTokenPath, logHandler(s.imdsV2TokenHandler))
	mux.HandleFunc(ec2CredPath, logHandler(s.ec2CredHandler))

	if len(s.options.Path) > 0 {
		// configure ECS http handler with logging
		mux.HandleFunc(s.options.Path, logHandler(s.ecsCredHandler))

		// print ECS credential endpoint message
		logger.Infof("ECS credential endpoint set to http://%s%s", s.listener.Addr().String(), s.options.Path)
		logger.Infof("Set the AWS_CONTAINER_CREDENTIALS_FULL_URI environment variable with the above value to allow programs to use it")
	} else if !strings.HasPrefix(s.listener.Addr().String(), DefaultEc2ImdsAddr) {
		// print non-default EC2 IMDS endpoint message
		logger.Infof("EC2 metadata endpoint set to http://%s/", s.listener.Addr().String())
		logger.Infof("Set the AWS_EC2_METADATA_SERVICE_ENDPOINT environment variable with the above value to allow programs to use it")
	}

	if len(s.options.Profile) > 0 {
		// since we don't have a valid http server yet, we need to bang on profileHandler() directly
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, profilePath,
			strings.NewReader(s.options.Profile))
		s.profileHandler(httptest.NewRecorder(), r)
		logger.Infof("Using initial profile '%s'", s.options.Profile)
	} else {
		logger.Infof("Access the web interface at http://%s and select a profile to begin", s.listener.Addr().String())
	}

	srv := new(http.Server)
	srv.Handler = mux
	defer cleanup(srv)

	installSigHandler(srv)
	return srv.Serve(s.listener)
}

func (s *metadataCredentialService) RunHeadless() error {
	s.clientOptions.MfaInputProvider = helpers.NewMfaTokenProvider(os.Stdin).ReadInput
	s.clientOptions.CredentialInputProvider = helpers.NewUserPasswordInputProvider(os.Stdin).ReadInput

	s.clientFactory = client.NewClientFactory(s.configResolver, s.clientOptions)

	// only configure the handlers useful when running without a browser, do not use request logging
	mux := http.NewServeMux()
	mux.HandleFunc(profilePath, s.profileHandler)
	mux.HandleFunc(imdsTokenPath, s.imdsV2TokenHandler)
	mux.HandleFunc(ec2CredPath, s.ec2CredHandler)

	if len(s.options.Path) > 0 {
		// configure ECS http handler without request logging
		mux.HandleFunc(s.options.Path, s.ecsCredHandler)
		logger.Debugf("ECS credential endpoint set to http://%s%s", s.listener.Addr().String(), s.options.Path)
	} else if !strings.HasPrefix(s.listener.Addr().String(), DefaultEc2ImdsAddr) {
		logger.Debugf("EC2 metadata endpoint set to http://%s/", s.listener.Addr().String())
	}

	if len(s.options.Profile) > 0 {
		// since we don't have a valid http server yet, we need to bang on profileHandler() directly
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, profilePath,
			strings.NewReader(s.options.Profile))
		s.profileHandler(httptest.NewRecorder(), r)
		logger.Debugf("Using initial profile '%s'", s.options.Profile)
	}

	srv := new(http.Server)
	srv.Handler = mux
	defer cleanup(srv)

	return srv.Serve(s.listener)
}

func (s *metadataCredentialService) profileHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Method == http.MethodPost {
		buf := make([]byte, 256) // if there's a profile name longer than this ... I mean, really
		n, err := r.Body.Read(buf)

		if err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		profile := string(buf[:n])
		cfg, err := s.configResolver.Config(profile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		cl, err := s.clientFactory.Get(cfg)
		if err != nil {
			// fixme - this could possibly be an auth error trying to initialize a saml or oidc client
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		s.awsConfig = cfg
		s.awsClient = cl

		logger.Debugf("updated profile to %s", cfg.ProfileName)
		_, _ = w.Write(nil)
	} else {
		if s.awsConfig == nil || len(s.awsConfig.ProfileName) < 1 {
			http.Error(w, "profile not set", http.StatusInternalServerError)
			return
		}
		logger.Debugf("profile: %s", s.awsConfig.ProfileName)
		_, _ = w.Write([]byte(s.awsConfig.ProfileName))
	}
}

func (s *metadataCredentialService) imdsV2TokenHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Method == http.MethodPut && len(r.Header.Get(`X-Aws-Ec2-Metadata-Token-Ttl-Seconds`)) > 0 {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("IamNOTaRealBoy!"))
		return
	}

	http.Error(w, "Not Implemented", http.StatusMethodNotAllowed)
}

func (s *metadataCredentialService) ec2CredHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	p := strings.Split(r.URL.Path, "/")[1:]
	if len(p[len(p)-1]) < 1 {
		_, _ = w.Write([]byte(s.awsConfig.ProfileName))
	} else {
		creds, err := s.awsClient.Credentials()
		if err != nil {
			logger.Errorf("Credentials: %v", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		ec2Creds, _ := creds.EC2() // error would only ever be json marshal failure
		logger.Debugf("EC2 CREDS: %s", ec2Creds)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(ec2Creds)
	}
}

func (s *metadataCredentialService) ecsCredHandler(w http.ResponseWriter, _ *http.Request) {
	creds, err := s.awsClient.Credentials()
	if err != nil {
		logger.Errorf("Credentials: %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	ecsCreds, _ := creds.ECS() // error would only ever be json marshal failure
	logger.Debugf("ECS CREDS: %s", ecsCreds)

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(ecsCreds)
}

func (s *metadataCredentialService) refreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && s.awsClient != nil {
		logger.Debugf("Expiring credentials for refresh")
		if err := s.awsClient.ClearCache(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("success"))
		return
	}
	http.Error(w, "unsupported http method", http.StatusMethodNotAllowed)
}

func (s *metadataCredentialService) listRolesHandler(w http.ResponseWriter, _ *http.Request) {
	roles, err := config.DefaultIniLoader.Roles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	body, err := json.Marshal(roles)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (s *metadataCredentialService) authHandler(w http.ResponseWriter, r *http.Request) {
	// todo
	http.NotFound(w, r)
}

func configureListener(addr string) (net.Listener, error) {
	if strings.HasPrefix(addr, DefaultEc2ImdsAddr) {
		// todo
		//  using default EC2 IMDS address, need to configure a network interface (eww)
		//  do drop privilege here too, since this requires root/admin authority
	}

	return net.Listen("tcp", addr)
}

func cleanup(srv *http.Server) {
	_ = srv.Shutdown(context.Background())

	if os.Getuid() == 0 && strings.HasPrefix(srv.Addr, DefaultEc2ImdsAddr) {
		// todo attempt DefaultEc2ImdsAddr teardown
	}
}

func installSigHandler(srv *http.Server) {
	sigCh := make(chan os.Signal, 5)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM)

	go func() {
		for {
			sig := <-sigCh
			logger.Debugf("Metadata service got signal: %s", sig.String())
			cleanup(srv)
		}
	}()
}

func logHandler(nextHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		nextHandler(rec, r)

		logger.Infof("%s %s %s %d %d", r.Method, r.URL.Path, r.Proto, rec.Code, rec.Body.Len())

		// rec.Result().Write() prints all of the details about the response, including the status line and such,
		// which is passed along in the body of the upstream writer. Need to be more specific/precise
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = rec.Body.WriteTo(w)
	}
}
