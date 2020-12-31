package metadata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/mmmorris1975/aws-runas/client"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/credentials/helpers"
	"github.com/mmmorris1975/aws-runas/metadata/templates"
	"github.com/mmmorris1975/aws-runas/shared"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/template"
)

const (
	DefaultEcsCredPath = "/credentials"
	DefaultEc2ImdsAddr = "169.254.169.254"

	imdsTokenPath  = "/latest/api/token" //nolint:gosec // remove false positive because Token is in the const name
	ec2CredPath    = "/latest/meta-data/iam/security-credentials/"
	authPath       = "/auth"
	mfaPath        = "/mfa"
	profilePath    = "/profile"
	newProfilePath = "/profile/custom"
	listRolesPath  = "/list-roles"
	refreshPath    = "/refresh"
)

var (
	logger shared.Logger = new(shared.DefaultLogger)
)

type Options struct {
	Path        string
	Profile     string
	Logger      shared.Logger
	AwsLogLevel aws.LogLevelType
	Headless    bool
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
	s.clientFactory = client.NewClientFactory(s.configResolver, s.clientOptions)

	mux := http.NewServeMux()
	mux.HandleFunc("/", logHandler(s.rootHandler))
	mux.HandleFunc(authPath, logHandler(s.authHandler))
	mux.HandleFunc(mfaPath, logHandler(s.mfaHandler))
	mux.HandleFunc(profilePath, logHandler(s.profileHandler))
	mux.HandleFunc(listRolesPath, logHandler(s.listRolesHandler))
	mux.HandleFunc(refreshPath, logHandler(s.refreshHandler))
	mux.HandleFunc(imdsTokenPath, logHandler(s.imdsV2TokenHandler))
	mux.HandleFunc(ec2CredPath, logHandler(s.ec2CredHandler))
	mux.HandleFunc(newProfilePath, logHandler(s.customProfileHandler))

	if len(s.options.Path) > 0 {
		// configure ECS http handlers with logging
		mux.HandleFunc(s.options.Path, logHandler(s.ecsCredHandler))
		mux.HandleFunc(s.options.Path+`/`, logHandler(s.ecsCredHandler))

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

	if !s.options.Headless {
		// install web-aware credential and mfa handlers after calling profileHandler() so that initial prompting for
		// missing authentication information is sent to the command line during startup.
		s.clientOptions.MfaInputProvider = func() (string, error) {
			return "", NewWebMfaRequiredError()
		}

		s.clientOptions.CredentialInputProvider = func(_ string, _ string) (string, string, error) {
			return "", "", NewWebAuthenticationError()
		}
	}

	srv := new(http.Server)
	srv.Handler = mux
	defer cleanup(srv)

	installSigHandler(srv)
	return srv.Serve(s.listener)
}

func (s *metadataCredentialService) RunNoApi() error {
	s.clientOptions.MfaInputProvider = helpers.NewMfaTokenProvider(os.Stdin).ReadInput
	s.clientOptions.CredentialInputProvider = helpers.NewUserPasswordInputProvider(os.Stdin).ReadInput

	s.clientFactory = client.NewClientFactory(s.configResolver, s.clientOptions)

	// only configure the handlers useful when running without a browser, do not use request logging
	mux := http.NewServeMux()
	mux.HandleFunc(profilePath, s.profileHandler)
	mux.HandleFunc(imdsTokenPath, s.imdsV2TokenHandler)
	mux.HandleFunc(ec2CredPath, s.ec2CredHandler)

	if len(s.options.Path) > 0 {
		// configure ECS http handlers without request logging
		mux.HandleFunc(s.options.Path, s.ecsCredHandler)
		mux.HandleFunc(s.options.Path+`/`, s.ecsCredHandler)
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

func (s *metadataCredentialService) rootHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/index.html", "index.htm":
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(templates.IndexHtml))
	case "/site.js":
		params := map[string]string{
			"profile_ep": profilePath,
			"roles_ep":   listRolesPath,
			"auth_ep":    authPath,
			"mfa_ep":     mfaPath,
			"custom_ep":  newProfilePath,
		}

		tmpl := template.Must(template.New("").Parse(templates.SiteJs))
		w.Header().Set("Content-Type", "application/javascript")
		if err := tmpl.Execute(w, params); err != nil {
			logger.Errorf("error executing template: %v", err)
		}
	case "/site.css":
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte(templates.SiteCss))
	default:
		http.NotFound(w, r)
	}
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

		s.awsConfig, s.awsClient, err = s.getConfigAndClient(string(buf[:n]))
		if err != nil {
			// this could possibly be an auth error trying to initialize a saml or oidc client
			s.handleAuthError(err, w)
			return
		}

		// fetch credentials after switching profile to see if we should re-auth while we have their attention
		if _, err = s.awsClient.Credentials(); err != nil {
			s.handleAuthError(err, w)
			return
		}

		logger.Debugf("updated profile to %s", s.awsConfig.ProfileName)
	} else {
		if s.awsConfig == nil || len(s.awsConfig.ProfileName) < 1 {
			http.Error(w, "profile not set", http.StatusInternalServerError)
			return
		}
		logger.Debugf("profile: %s", s.awsConfig.ProfileName)
	}

	authUrl := s.awsConfig.SamlUrl
	username := s.awsConfig.SamlUsername
	if len(s.awsConfig.WebIdentityClientId) > 0 {
		authUrl = s.awsConfig.WebIdentityUsername
		username = s.awsConfig.WebIdentityUsername
	}

	profile := map[string]string{
		"role_arn":     s.awsConfig.RoleArn,
		"external_id":  s.awsConfig.ExternalId,
		"auth_url":     authUrl,
		"username":     username,
		"jump_role":    s.awsConfig.JumpRoleArn,
		"client_id":    s.awsConfig.WebIdentityClientId,
		"redirect_uri": s.awsConfig.WebIdentityRedirectUri,
	}

	if s.awsConfig.SourceProfile() != nil {
		profile["source_profile"] = s.awsConfig.SourceProfile().ProfileName
	}

	j, _ := json.Marshal(profile)
	_, _ = w.Write(j)
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
			s.handleAuthError(err, w)
			return
		}
		ec2Creds, _ := creds.EC2() // error would only ever be json marshal failure
		logger.Debugf("EC2 CREDS: %s", ec2Creds)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(ec2Creds)
	}
}

// Extend the behavior of the ECS credential endpoint so it accepts additional path elements beyond the
// base path configured for the handler.  Any extra path information is interpreted as a profile name
// for fetching credentials.  The "standard" behavior still works as expected, and calls to the base path
// will return credentials for the profile specified at startup, or the profile configured via the /profile
// endpoint.  But now something like: http://127.0.0.1:54321/credentials/my_profile will get credentials
// for 'my_profile', instead of the "global" profile.  This will enable folks to set the
// AWS_CONTAINER_CREDENTIALS_FULL_URI environment variable to context-specific profiles without needing to
// run dedicated services for each profile.
func (s *metadataCredentialService) ecsCredHandler(w http.ResponseWriter, r *http.Request) {
	var creds *credentials.Credentials
	var err error

	cl := s.awsClient
	if cl == nil {
		cl, err = s.clientFactory.Get(s.awsConfig)
		if err != nil {
			s.handleAuthError(err, w)
			return
		}
	}

	if s.options.Path != r.URL.Path {
		// use requested profile
		// I can't think of a good way to avoid needing to resolve the profile configuration and client
		// with each request (aside from implementing an internal mapping of profile to config and client,
		// which feels like a premature optimization at this point)
		parts := strings.Split(r.URL.Path, `/`)
		profile := parts[len(parts)-1]

		var cfg *config.AwsConfig
		cfg, cl, err = s.getConfigAndClient(profile)
		if err != nil {
			logger.Errorf("Client fetch: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// this really only exists to facilitate testing, since clientFactory is a concrete type.
		// Ideally, we make it an interface and mock it, but for the 1 case we need it for, this is sufficient
		if cfg.SamlProvider == "mock" {
			cl = s.awsClient
		}
	}

	creds, err = cl.Credentials()
	if err != nil {
		s.handleAuthError(err, w)
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
	// don't clear username or password from config state after completing this handler, we may need them later (mfa)
	defer r.Body.Close()
	var err error

	if err = r.ParseForm(); err != nil {
		s.options.Logger.Errorf("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user := r.Form.Get("username")
	pass := r.Form.Get("password")
	s.awsConfig.SamlUsername = user
	s.awsConfig.WebIdentityUsername = user

	creds := new(config.AwsCredentials)
	creds.SamlPassword = pass
	creds.WebIdentityPassword = pass

	s.clientOptions.CommandCredentials = creds
	s.awsClient, err = s.clientFactory.Get(s.awsConfig)
	if err != nil {
		s.options.Logger.Errorf("%v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if _, err = s.awsClient.Credentials(); err != nil {
		s.options.Logger.Errorf("%v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	_, _ = w.Write(nil)
}

func (s *metadataCredentialService) mfaHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	defer func() { s.awsConfig.MfaCode = "" }()
	var err error

	if err = r.ParseForm(); err != nil {
		s.options.Logger.Errorf("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.awsConfig.MfaCode = r.Form.Get("mfa")
	s.awsClient, err = s.clientFactory.Get(s.awsConfig)
	if err != nil {
		s.options.Logger.Errorf("%v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if _, err = s.awsClient.Credentials(); err != nil {
		s.options.Logger.Errorf("%v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	_, _ = w.Write(nil)
}

func (s *metadataCredentialService) customProfileHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var err error

	if err = r.ParseForm(); err != nil {
		s.options.Logger.Errorf("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var newCred *config.AwsCredentials
	newCfg := new(config.AwsConfig)
	newCfg.RoleArn = r.Form.Get("role-arn")

	switch r.Form.Get("adv-type") {
	case "iam":
		newCfg.ExternalId = r.Form.Get("external-id")
		newCfg.SrcProfile = r.Form.Get("source-profile")
	case "saml":
		newCfg.SamlUrl = r.Form.Get("auth-url")
		newCfg.SamlUsername = r.Form.Get("username")
		newCfg.JumpRoleArn = r.Form.Get("jump-role")

		newCred = new(config.AwsCredentials)
		newCred.SamlPassword = r.Form.Get("password")
	case "oidc":
		newCfg.WebIdentityUrl = r.Form.Get("auth-url")
		newCfg.WebIdentityUsername = r.Form.Get("username")
		newCfg.WebIdentityClientId = r.Form.Get("client-id")
		newCfg.WebIdentityRedirectUri = r.Form.Get("redirect-uri")
		newCfg.JumpRoleArn = r.Form.Get("jump-role")

		newCred = new(config.AwsCredentials)
		newCred.WebIdentityPassword = r.Form.Get("password")
	default:
		http.Error(w, "Invalid Configuration Type", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPost:
		// update running config without persisting to config file
		// clear ProfileName so we don't whack (or possibly use?) the cache for an existing profile
		s.awsConfig.MergeIn(newCfg)
		s.awsConfig.ProfileName = ""

		if err = s.awsConfig.Validate(); err != nil {
			http.Error(w, fmt.Sprintf("Invalid Configuration: %v", err), http.StatusBadRequest)
			return
		}
	case http.MethodPut:
		// todo - save as new profile in config file (switch to profile after save?)
	default:
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}
}

func (s *metadataCredentialService) getConfigAndClient(profile string) (cfg *config.AwsConfig, cl client.AwsClient, err error) {
	cfg, err = s.configResolver.Config(profile)
	if err != nil {
		return nil, nil, err
	}

	// ewww, testing-specific code in actual code
	if cfg.SamlProvider == "mock" && s.awsClient != nil {
		return cfg, s.awsClient, nil
	}

	cl, err = s.clientFactory.Get(cfg)
	if err != nil {
		return cfg, nil, err
	}

	return cfg, cl, err
}

func (s *metadataCredentialService) handleAuthError(err error, w http.ResponseWriter) {
	if e, ok := err.(WebAuthenticationError); ok {
		m := make(map[string]string)
		switch e.Error() {
		case "MFA":
		default:
			m["username"] = ""
			if s.awsConfig != nil {
				m["username"] = s.awsConfig.SamlUsername
			}
		}

		body, _ := json.Marshal(m)
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("X-AwsRunas-Authentication-Type", e.Error())
		_, _ = w.Write(body)
		return
	}

	logger.Errorf("handleAuthError: %v", err)
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func configureListener(addr string) (net.Listener, error) {
	if strings.HasPrefix(addr, DefaultEc2ImdsAddr) {
		// DefaultEc2ImdsAddr requires that we setup the address on an interface. (eww, root/admin is required!)
		// Under the covers, it relies on OS-specific commands, but it avoids a bunch of other ugliness to make
		// things work (iptables for linux, not sure about others ... maybe the route command?)
		iface, err := discoverLoopback()
		if err != nil {
			return nil, err
		}

		if err = addAddress(iface, DefaultEc2ImdsAddr+"/22"); err != nil {
			return nil, err
		}

		var lsnr net.Listener
		lsnr, err = net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}

		// drop privilege after configuring interface and binding to privileged port so we avoid running
		// the rest of the process with elevated privileges
		return lsnr, dropPrivileges()
	}

	return net.Listen("tcp", addr)
}

func cleanup(srv *http.Server) {
	_ = srv.Shutdown(context.Background())

	if os.Getuid() == 0 && strings.HasPrefix(srv.Addr, DefaultEc2ImdsAddr) {
		_ = removeAddress(DefaultEc2ImdsAddr)
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
