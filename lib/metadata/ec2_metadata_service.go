package metadata

import (
	"aws-runas/lib/cache"
	cfglib "aws-runas/lib/config"
	credlib "aws-runas/lib/credentials"
	"aws-runas/lib/identity"
	"aws-runas/lib/saml"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/mmmorris1975/aws-config/config"
	"github.com/mmmorris1975/simple-logger/logger"
	"github.com/syndtr/gocapability/capability"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	ec2MdSvcCredPath = "/latest/meta-data/iam/security-credentials/"
	authPath         = "/auth"
	profilePath      = "/profile"
	listRolesPath    = "/list-roles"
	refreshPath      = "/refresh"
	imdsV2Token      = "/latest/api/token"
	imdsAddr         = "169.254.169.254"
)

var (
	ec2MdSvcAddr *net.IPAddr

	log        *logger.Logger
	s          *session.Session
	usr        *identity.Identity
	profile    *cfglib.AwsConfig
	cacheDir   string
	cr         config.AwsConfigResolver
	cred       *credentials.Credentials
	samlClient saml.AwsClient

	sigCh = make(chan os.Signal, 3)
	srv   = new(http.Server)

	errCredsRequired = errors.New("credentials required")
	errMfaRequired   = errors.New("mfa token required")

	siteJs string
)

func init() {
	ec2MdSvcAddr, _ = net.ResolveIPAddr("ip", imdsAddr)

	m := make(map[string]interface{})
	m["auth_ep"] = authPath
	m["profile_ep"] = profilePath
	m["refresh_ep"] = refreshPath
	m["roles_ep"] = listRolesPath

	b := new(strings.Builder)
	if err := siteJsTmpl.Execute(b, m); err != nil {
		panic(err)
	}
	siteJs = b.String()
}

type handlerError struct {
	error
	msg  string
	code int
}

func newHandlerError(msg string, code int) *handlerError {
	return &handlerError{msg: msg, code: code}
}

func (e *handlerError) Error() string {
	return e.msg
}

type ec2MetadataOutput struct {
	Code            string
	Type            string
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      time.Time
	LastUpdated     time.Time
}

type credentialPrompt struct {
	Username *string `json:"username,omitempty"`
	Password *string `json:"password,omitempty"`
	MfaCode  *string `json:"mfa_code,omitempty"`
	Type     string  `json:"type"`
}

// EC2MetadataInput is a struct to provide options for configuring the state of the metadata service at startup
type EC2MetadataInput struct {
	// Config is the AwsConfig for a profile provided at service startup
	Config *cfglib.AwsConfig
	// Logger is the logger object to configure for the service
	Logger *logger.Logger
	// Session is the initial AWS session.Session object to use at service startup
	Session *session.Session
	// CacheDir is the path used to cache the credentials. Set to an empty string to disable caching.
	CacheDir string
	// SamlClient is an optional AWS SAML client to pre-configure the initial SAML client data
	SamlClient saml.AwsClient
}

// NewEC2MetadataService starts an HTTP server which will listen on the EC2 metadata service address for handling
// requests for instance role credentials.  SDKs will do an HTTP GET at '/latest/meta-data/iam/security-credentials/',
// which returns the name of the instance role in use, it then appends that value to the previous request url
// and expects the response body to contain the credential data in json format.
func NewEC2MetadataService(opts *EC2MetadataInput) error {
	if err := handleOptions(opts); err != nil {
		return err
	}

	if runtime.GOOS == "linux" {
		log.Debug("setting Linux capabilities")
		if err := linuxSetCap(); err != nil {
			return err
		}
	}

	lo, err := setupInterface()
	if err != nil {
		return err
	}
	defer func() {
		if os.Getuid() == 0 {
			// this will only work if root/administrator
			if err := removeAddress(lo, ec2MdSvcAddr); err != nil {
				log.Debugf("Error removing network config: %v", err)
			}
		}
	}()

	hp := net.JoinHostPort(ec2MdSvcAddr.String(), "80")
	l, err := net.Listen("tcp4", hp)
	if err != nil {
		log.Fatalf("Error creating listener: %v", err)
	}

	if err := dropPrivileges(); err != nil {
		log.Fatalf("Error dropping privileges, will not continue: %v", err)
	}

	// install signal handler, after the "dangerous" bits, to shutdown gracefully when we get a ^C (SIGINT) or ^\ (SIGQUIT)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGQUIT)
	go func() {
		for {
			sig := <-sigCh
			log.Debugf("Metadata service got signal: %s", sig.String())
			if srv != nil {
				if err := srv.Shutdown(context.Background()); err != nil {
					log.Debugf("Error shutting down metadata service: %v", err)
				}
			}
		}
	}()

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/site.js", jsHandler)
	http.HandleFunc(authPath, authHandler)
	http.HandleFunc(profilePath, profileHandler)
	http.HandleFunc(ec2MdSvcCredPath, credHandler)
	http.HandleFunc(listRolesPath, listRoleHandler)
	http.HandleFunc(refreshPath, refreshHandler)
	http.Handle(imdsV2Token, http.NotFoundHandler()) // disable IMDSv2 (for now?)

	log.Infoln("EC2 Metadata Service ready!")

	if len(profile.Profile) > 0 {
		wr := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, profilePath, strings.NewReader(profile.Profile))
		profileHandler(wr, req)
		log.Infof("Using initial profile '%s'", profile.Profile)
	} else {
		log.Infof("Access the web interface at http://%s and select a role to begin", hp)
	}
	return srv.Serve(l)
}

func handleOptions(opts *EC2MetadataInput) error {
	log = opts.Logger
	if log == nil {
		log = logger.StdLogger
	}

	profile = opts.Config        // may be nil/empty if no profile passed at startup, it's not an error
	samlClient = opts.SamlClient // may be nil/empty if we're not starting with a SAML profile, it's not an error

	s = opts.Session
	if s == nil {
		return errors.New("invalid session provided")
	}

	cacheDir = opts.CacheDir
	if len(cacheDir) < 1 {
		d, err := os.UserCacheDir()
		if err != nil {
			log.Debugf("Error finding User Cache Dir: %v, using Temp Dir", err)
			d = os.TempDir()
		}
		cacheDir = d
	}

	var err error
	cr, err = config.NewAwsConfigResolver(nil)
	return err
}

// Set capabilities to allow us to run without sudo or setuid on Linux. After installing the tool, you must run
// sudo /sbin/setcap "cap_net_admin,cap_net_bind_service,cap_setgid,cap_setuid=p" aws-runas
// to enable the use of these capability settings.  (If using the DEB or RPM packages, this is done as part of the
// package install/update.)
// You can still execute aws-runas wrapped in sudo, if you prefer to not use the capabilities feature.
func linuxSetCap() error {
	caps := capability.CAPS | capability.AMBIENT
	c, err := capability.NewPid2(0)
	if err != nil {
		return err
	}

	c.Set(caps, capability.CAP_SETGID, capability.CAP_SETUID, capability.CAP_NET_BIND_SERVICE, capability.CAP_NET_ADMIN)
	return c.Apply(caps)
}

// This is really the only semi-sane way to configure the necessary networking, it still requires
// admin/sudo privileges on the system, and relies on OS-specific commands under the covers.
// However, it avoids a bunch of other ugliness to make things work (iptables for linux, not
// sure about others ... maybe the route command? Regardless, even those require admin/sudo)
func setupInterface() (string, error) {
	lo, err := discoverLoopback()
	if err != nil {
		return "", err
	}
	log.Debugf("LOOPBACK INTERFACE: %s", lo)

	if err := addAddress(lo, ec2MdSvcAddr); err != nil {
		if err := removeAddress(lo, ec2MdSvcAddr); err != nil {
			return "", err
		}

		if err := addAddress(lo, ec2MdSvcAddr); err != nil {
			return "", err
		}
	}
	return lo, err
}

func writeResponse(w http.ResponseWriter, r *http.Request, body string, code int) {
	if code < 100 {
		code = http.StatusOK
	}

	if len(w.Header().Get("Content-Type")) < 1 {
		w.Header().Set("Content-Type", "text/plain")
	}

	contentLength := strconv.Itoa(len(body))
	w.Header().Set("Content-Length", contentLength)
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:63342")
	w.WriteHeader(code)
	if _, err := w.Write([]byte(body)); err != nil {
		log.Error(err)
	}

	log.Infof("%s %s %s %d %s", r.Method, r.URL.Path, r.Proto, code, contentLength)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	writeResponse(w, r, indexHtml, http.StatusOK)
}

func jsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript")
	writeResponse(w, r, siteJs, http.StatusOK)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		p, hErr := getProfileConfig(r.Body)
		if hErr != nil {
			writeResponse(w, r, hErr.Error(), hErr.code)
			return
		}
		log.Debugf("retrieved profile %+v", p)

		if profile == nil || p.SourceProfile != profile.SourceProfile {
			if err := updateSession(p.SourceProfile); err != nil {
				log.Debugf("error updating session: %v", err)
			}
		}

		var err error
		var t time.Time
		profile, err = cfglib.Wrap(p)
		if err != nil {
			writeResponse(w, r, fmt.Sprintf("configuration error: %v", err), http.StatusInternalServerError)
			return
		}

		var idp identity.Provider
		if profile.SamlAuthUrl != nil && len(profile.SamlAuthUrl.String()) > 0 {
			if hErr := createSamlClient(); hErr != nil {
				writeResponse(w, r, hErr.Error(), hErr.code)
				return
			}

			// We must fetch the SamlResponse to have valid identity information, this may require auth/re-auth
			_, err = samlClient.AwsSaml()
			if err != nil {
				// assume any error indicates the need to do SAML authentication
				samlProfileAuthError(w, r)
				return
			}
			d, _ := samlClient.GetSessionDuration()
			t = time.Now().Add(time.Duration(d) * time.Second)

			idp = samlClient
		} else {
			cred = createSessionCredentials()
			log.Debugf("CREDS: %+v", cred)

			if _, err = cred.Get(); err != nil {
				iamProfileAuthError(w, r, err)
				return
			}
			t, _ = cred.ExpiresAt()

			idp = identity.NewAwsIdentityProvider(s).WithLogger(log)
		}

		usr, err = idp.GetIdentity()
		if err != nil {
			log.Errorf("error resolving identity: %v", err)
		}

		writeResponse(w, r, t.Local().String(), http.StatusOK)
	} else {
		sendProfile(w, r)
	}
}

func samlProfileAuthError(w http.ResponseWriter, r *http.Request) {
	pr := credentialPrompt{
		Username: aws.String(profile.SamlUsername),
		Password: aws.String(""),
		Type:     "saml",
	}

	if samlClient.Client().MfaType == saml.MfaTypeCode {
		pr.MfaCode = aws.String("")
	}
	body, _ := json.Marshal(pr)

	writeResponse(w, r, string(body), http.StatusUnauthorized)
}

func iamProfileAuthError(w http.ResponseWriter, r *http.Request, err error) {
	pr := credentialPrompt{MfaCode: aws.String(""), Type: "session"}
	body, _ := json.Marshal(pr)

	switch t := err.(type) {
	case *credlib.ErrMfaRequired:
		writeResponse(w, r, string(body), http.StatusUnauthorized)
		return
	case awserr.Error:
		if t.Code() == "AccessDenied" && strings.HasPrefix(t.Message(), "MultiFactorAuthentication failed") {
			writeResponse(w, r, string(body), http.StatusUnauthorized)
			return
		}
	}

	log.Error(err)
	writeResponse(w, r, "Error getting session credentials", http.StatusInternalServerError)
}

func createSessionCredentials(mfa ...string) *credentials.Credentials {
	return credlib.NewSessionTokenCredentials(s, func(pv *credlib.SessionTokenProvider) {
		pv.Duration = profile.SessionTokenDuration
		pv.SerialNumber = profile.MfaSerial
		pv.Log = log
		pv.TokenProvider = func() (string, error) {
			return "", new(credlib.ErrMfaRequired)
		}

		if len(mfa) > 0 {
			pv.TokenCode = mfa[0]
		}

		cf := cacheFile(fmt.Sprintf(".aws_session_token_%s", profile.SourceProfile))
		if len(cf) > 0 {
			pv.Cache = cache.NewFileCredentialCache(cf)
		}
	})
}

func createSamlClient() *handlerError {
	jar, err := cache.NewCookieJarFile(cacheFile(".saml-client.cookies"))
	if err != nil {
		return newHandlerError(err.Error(), http.StatusInternalServerError)
	}

	sc, err := saml.GetClient(profile.SamlProvider, profile.SamlAuthUrl.String(), func(s *saml.BaseAwsClient) {
		s.Username = profile.SamlUsername
		s.Password = os.Getenv("SAML_PASSWORD")
		s.CredProvider = func(u string, p string) (string, string, error) {
			return "", "", errCredsRequired
		}
		s.MfaTokenProvider = func() (string, error) {
			return "", errMfaRequired
		}
		s.SetCookieJar(jar)
	})

	if err != nil {
		return newHandlerError(err.Error(), http.StatusInternalServerError)
	}
	samlClient = sc

	return nil
}

func getProfileConfig(r io.Reader) (*config.AwsConfig, *handlerError) {
	if r == nil {
		return nil, newHandlerError("nil reader", http.StatusInternalServerError)
	}

	b := make([]byte, 4096)
	n, err := r.Read(b)
	if err != nil && err != io.EOF {
		log.Error(err)
		return nil, newHandlerError("Error reading request data", http.StatusInternalServerError)
	}

	in := string(b[:n])
	p, err := cr.Resolve(in)
	if err != nil {
		log.Error(err)
		return nil, newHandlerError("Error resolving profile config", http.StatusInternalServerError)
	}

	return p, nil
}

func updateSession(p string) (err error) {
	var sc *aws.Config
	if s != nil {
		sc = s.Config
	} else {
		sc = new(aws.Config).WithCredentialsChainVerboseErrors(true).WithLogger(log)
		if log.Level == logger.DEBUG {
			sc.LogLevel = aws.LogLevel(aws.LogDebug)
		}
	}

	o := session.Options{Config: *sc, Profile: p}
	s = session.Must(session.NewSessionWithOptions(o))

	return nil
}

func sendProfile(w http.ResponseWriter, r *http.Request) {
	// return name of active role
	writeResponse(w, r, profile.Profile, http.StatusOK)
}

func listRoleHandler(w http.ResponseWriter, r *http.Request) {
	b, err := json.Marshal(listRoles())
	if err != nil {
		writeResponse(w, r, "error building role list", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	writeResponse(w, r, string(b), http.StatusOK)
}

func listRoles() []string {
	if cr != nil {
		return cr.ListProfiles(true)
	}
	return []string{}
}

func cacheFile(p string) string {
	if len(cacheDir) > 0 && len(p) > 0 {
		return filepath.Join(cacheDir, p)
	}
	return ""
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	auth, hErr := getAuth(r.Body)
	if hErr != nil {
		writeResponse(w, r, hErr.Error(), hErr.code)
		return
	}

	var idp identity.Provider
	var err error

	if auth.Type == "saml" {
		sc := samlClient.Client()

		if auth.Username != nil {
			sc.Username = *auth.Username
		}

		if auth.Password != nil {
			sc.Password = *auth.Password
		}

		if auth.MfaCode != nil {
			sc.MfaToken = *auth.MfaCode
		}

		err = samlClient.Authenticate()
		if errors.Is(err, errCredsRequired) {
			// invalid username or password
			auth.Password = aws.String("")
			log.Error("SAML credentials required")
			writeResponse(w, r, "invalid saml credentials", http.StatusUnauthorized)
			return
		} else if errors.Is(err, errMfaRequired) {
			// invalid mfa
			log.Error("SAML MFA required")
			writeResponse(w, r, "saml mfa required", http.StatusUnauthorized)
			return
		} else if err != nil {
			log.Errorf("error doing SAML authentication: %v", err)
			writeResponse(w, r, "Login failed", http.StatusUnauthorized)
			return
		}

		if _, err = samlClient.AwsSaml(); err != nil {
			log.Errorf("error getting AWS SAML: %v", err)
			writeResponse(w, r, "Error getting AWS SAML", http.StatusInternalServerError)
			return
		}

		idp = samlClient
	} else {
		cred = createSessionCredentials(*auth.MfaCode)

		if _, err = cred.Get(); err != nil {
			log.Errorf("error getting session credentials: %v", err)
			writeResponse(w, r, "Error getting session credentials", http.StatusUnauthorized)
			return
		}

		idp = identity.NewAwsIdentityProvider(s).WithLogger(log)
	}

	usr, err = idp.GetIdentity()
	if err != nil {
		log.Errorf("error getting identity information: %v", err)
		writeResponse(w, r, "Error getting identity information", http.StatusInternalServerError)
		return
	}

	writeResponse(w, r, "", http.StatusOK)
}

func getAuth(r io.ReadCloser) (*credentialPrompt, *handlerError) {
	if r == nil {
		return nil, newHandlerError("nil reader", http.StatusInternalServerError)
	}
	defer r.Close()

	b := make([]byte, 1024) // limit the size of the body we'll accept
	n, err := r.Read(b)
	if err != nil && err != io.EOF {
		log.Error(err)
		return nil, newHandlerError("Error reading request data", http.StatusInternalServerError)
	}

	pr := new(credentialPrompt)
	if err = json.Unmarshal(b[:n], pr); err != nil {
		log.Error(err)
		return nil, newHandlerError("Error unmarshaling credentials", http.StatusInternalServerError)
	}

	return pr, nil
}

func credHandler(w http.ResponseWriter, r *http.Request) {
	var b []byte
	var err error

	p := strings.Split(r.URL.Path, "/")[1:]
	if len(p[len(p)-1]) < 1 {
		sendProfile(w, r)
	} else {
		if profile.SamlAuthUrl != nil && len(profile.SamlAuthUrl.String()) > 0 {
			// assume role with SAML
			b, err = assumeSamlRole()
		} else {
			// assume IAM role
			b, err = assumeRole()
		}

		if err != nil {
			log.Errorf("AssumeRole: %v", err)
			writeResponse(w, r, "Error getting role credentials", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		writeResponse(w, r, string(b), http.StatusOK)
	}
}

func assumeRoleCredentials(c client.ConfigProvider) *credentials.Credentials {
	return credlib.NewAssumeRoleCredentials(c, profile.RoleArn, func(p *credlib.AssumeRoleProvider) {
		p.Log = log
		p.RoleSessionName = usr.Username
		p.ExternalID = profile.ExternalId
		p.Duration = credlib.AssumeRoleDefaultDuration
		p.ExpiryWindow = p.Duration / 10
	})
}

func fetchCredentials(c *credentials.Credentials) ([]byte, error) {
	v, err := c.Get()
	if err != nil {
		return nil, err
	}

	// 1 second more than the minimum Assume Role credential duration is the absolute minimum Expiration time so that
	// the default awscli logic won't think our credentials are expired, and send a duplicate request.
	output := ec2MetadataOutput{
		Code:            "Success",
		Type:            "AWS-HMAC",
		AccessKeyId:     v.AccessKeyID,
		SecretAccessKey: v.SecretAccessKey,
		Token:           v.SessionToken,
		Expiration:      time.Now().Add(credlib.AssumeRoleMinDuration).Add(1 * time.Second).UTC(),
		LastUpdated:     time.Now().UTC(),
	}
	log.Debugf("%+v", output)

	return json.Marshal(output)
}

func assumeRole() ([]byte, error) {
	log.Debugf("ROLE ARN: %s", profile.RoleArn)
	ar := assumeRoleCredentials(s.Copy(new(aws.Config).WithCredentials(cred)))
	return fetchCredentials(ar)
}

func assumeSamlRole() ([]byte, error) {
	var c *credentials.Credentials

	samlDoc, err := samlClient.AwsSaml()
	if err != nil {
		// todo handle error ... maybe?  the workflow before we get here requires that we've already called this successfully
	}

	sc := credlib.NewSamlRoleCredentials(s, profile.RoleArn, samlDoc, func(p *credlib.SamlRoleProvider) {
		p.Log = log
		p.RoleSessionName = usr.Username
		p.Duration = credlib.AssumeRoleDefaultDuration

		if len(profile.JumpRoleArn.Resource) > 0 {
			p.RoleARN = profile.JumpRoleArn.String()

			parts := strings.Split(profile.JumpRoleArn.Resource, "/")
			cf := fmt.Sprintf(".aws_saml_role_%s-%s", profile.JumpRoleArn.AccountID, parts[len(parts)-1])
			p.Cache = cache.NewFileCredentialCache(cacheFile(cf))

			profile.MfaSerial = "" // explicitly unset MfaSerial, just to be extra sure
		}

		p.ExpiryWindow = p.Duration / 10
	})

	if len(profile.JumpRoleArn.Resource) > 0 {
		c = assumeRoleCredentials(s.Copy(new(aws.Config).WithCredentials(sc)))
	} else {
		c = sc
	}

	return fetchCredentials(c)
}

// only actually works for IAM roles, not SAML roles, since we don't cache the Assumed Role credentials
// only the IAM Session Token credentials, which aren't used with SAML
func refreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && cred != nil {
		log.Debug("Expiring credentials for refresh")
		cred.Expire()

		if profile != nil {
			cf := cacheFile(fmt.Sprintf(".aws_session_token_%s", profile.SourceProfile))
			if len(cf) > 0 {
				if err := os.Remove(cf); err != nil {
					log.Debugf("Error removing cached credentials: %v", err)
				}
			}
		}
	}
	writeResponse(w, r, "success", http.StatusOK)
}

var indexHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1,shrink-to-fit=no"/>
    <title>aws-runas - AWS Metadata Credential Server</title>
    <script src="site.js"></script>
    <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
    <style type="text/css">
        body {
            background-color: navy;
            font-family: Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
        }

        main {
            min-width: 30em;
            max-width: 33em;
            margin: auto;
        }

        #refresh {
            background-color: crimson;
            border: 2px solid crimson;
            color: white;
            margin-left: 1.25em;
        }

        #refresh:hover {
            background-color: white;
            border: 2px solid crimson;
            color: crimson;
        }

        #mfa-prompt {
            min-width: 14em;
            max-width: 16em;
        }

        #cred-prompt {
            min-width: 22.5em;
            max-width: 27.5em;
        }

        .cred-input {
            width: 100%;
        }

        .cred-submit {
            margin-top: 0.5em;
            display: block;
            width: 100%;
            font-size: large;
            font-weight: bold;
            padding: 0.5em 1em;
            border-radius: 0.33em;
            color: white;
            background-color: darkblue;
            border: 1px solid darkblue;
        }

        .cred-submit:hover {
            background-color: white;
            border: 1px solid darkblue;
            color: darkblue;
        }
    </style>
</head>
<body class="w3-large w3-padding">
<div id="cred-modal" class="w3-modal">
    <div id="cred-prompt" class="w3-card-4 w3-padding w3-white w3-modal-content">
        <span id="login-message" class="w3-center w3-text-red"></span>
        <span onclick="document.getElementById('cred-modal').style.display='none'"
              class="w3-button w3-hover-red w3-display-topright" title="Close">&times;</span>
        <br>
        <form class="w3-container" onsubmit="return doAuth()">
            <fieldset>
                <legend>Enter SAML Credentials</legend>
                <div class="w3-row w3-margin-bottom">
                    <div class="w3-quarter">
                        <label for="username"><b>Username</b></label>
                    </div>
                    <div class="w3-rest">
                        <input id="username" name="username" type="text" required class="w3-border w3-round cred-input">
                    </div>
                </div>
                <div class="w3-row">
                    <div class="w3-quarter">
                        <label for="password"><b>Password</b></label>
                    </div>
                    <div class="w3-rest">
                        <input id="password" name="password" type="password" required class="w3-border w3-round cred-input">
                    </div>
                </div>
            </fieldset>
            <input id="cred-type" name="cred-type" type="hidden" value="saml">
            <button type="submit" class="w3-btn w3-round w3-block w3-margin-top cred-submit">
                Login
            </button>
        </form>
    </div>
</div>
<div id="mfa-modal" class="w3-modal">
    <div id="mfa-prompt" class="w3-card-4 w3-padding w3-white w3-modal-content">
        <span id="mfa-message" class="w3-center w3-text-red"></span>
        <span onclick="document.getElementById('mfa-modal').style.display='none'"
              class="w3-button w3-hover-red w3-display-topright" title="Close">&times;</span>
        <br>
        <form class="w3-container" onsubmit="return doMfa()">
            <fieldset>
                <legend>Enter MFA Code</legend>
                <label for="mfa"><b>MFA Code</b></label>
                <input id="mfa" name="mfa" type="text" size="8" required class="w3-border w3-round">
            </fieldset>
            <input id="mfa-type" name="cred-type" type="hidden" value="saml">
            <button type="submit" class="w3-btn w3-round w3-block w3-margin-top cred-submit">
                Submit
            </button>
        </form>
    </div>
</div>
<main class="w3-white w3-padding w3-margin-top w3-card-4 w3-round-large">
    <div id="title" class="w3-center"><h2>EC2 Metadata Service Role Selector</h2></div>

    <div id="form" class="w3-container w3-center">
        <form>
            <label for="roles"><b>Roles</b></label>
            <select id="roles" name="roles" onchange="postProfile(this.value)">
                <option value="">-- Select Role--</option>
            </select>
            <button type="button" id="refresh" name="refresh" onclick="doRefresh()" class="w3-btn w3-round"
                    title="Force a refresh of the credentials, may require re-authentication or re-entering MFA code">
                Refresh Now
            </button>
        </form>
    </div>

    <div id="message" class="w3-margin-top w3-center"></div>
</main>
</body>
</html>
`

var siteJsTmpl = template.Must(template.New("").Parse(`
function postProfile(role) {
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        if (this.readyState === 4) {
            if (this.status === 200) {
                let data = this.responseText;
                document.getElementById("message").innerHTML = "Credentials will expire on <i>" + data + "</i>"
            } else if (this.status === 401) {
                let o = JSON.parse(this.responseText);
                if (o.type === "saml") {
                    document.getElementById("username").value = o.username;
                    document.getElementById("cred-type").value = o.type;
                    document.getElementById("cred-modal").style.display = 'block';
                } else {
                    document.getElementById("mfa-type").value = o.type;
                    document.getElementById("mfa-modal").style.display = 'block';
                    document.getElementById("mfa").focus();
                }
            } else {
                console.log("profile POST returned " + this.status + ": " + this.responseText);
            }
        }
    };

    xhr.open("POST", "{{.profile_ep}}");
    xhr.send(role);
    return false
}

function refreshRoles() {
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        if (this.readyState === 4) {
            if (this.status === 200) {
                let sel = document.getElementById("roles");
                let j = JSON.parse(this.responseText);
                for (const i in j) {
                    sel.options.add(new Option(j[i]));
                }
            } else {
                console.log("list-roles returned " + this.status + ": " + this.responseText);
            }
        }
    };

    xhr.open("GET", "{{.roles_ep}}");
    xhr.send();
    return false;
}

function selectRole() {
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        if (this.readyState === 4) {
            if (this.status === 200) {
                let role = this.responseText;
                let opts = document.getElementById("roles").options;

                for (const o in opts) {
                    let opt = opts[o];
                    if (opt.text === role) {
                        opt.selected = true;
                        postProfile(role);
                        break;
                    } else {
                        opts[0].selected = true;
                    }
                }
            } else {
                console.log("profile GET returned " + this.status + ": " + this.responseText);
            }
        }
    };

    xhr.open("GET", "{{.profile_ep}}");
    xhr.send();
    return false;
}

function doRefresh() {
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        if (this.readyState === 4) {
            if (this.status === 200) {
                let r = document.getElementById("roles");
                postProfile(r.options[r.selectedIndex].text);
            } else {
                console.log("refresh returned " + this.status + ": " + this.responseText);
            }
        }
    };

    xhr.open("POST", "{{.refresh_ep}}");
    xhr.send();
    return false;
}

function doAuth() {
    let o = {
        username: document.getElementById("username").value,
        password: document.getElementById("password").value,
        type: document.getElementById("cred-type").value
    };
    console.log(JSON.stringify(o));

    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        if (this.readyState === 4) {
            if (this.status === 200) {
                document.getElementById("cred-modal").style.display = 'none';
                document.getElementById("password").value = "";
            } else if (this.status === 401) {
                if (this.responseText === "saml mfa required") {
                    document.getElementById("cred-modal").style.display = 'none';
                    document.getElementById('mfa-modal').style.display = 'block';
                    document.getElementById("mfa").focus();
                } else {
                    document.getElementById("login-message").innerText = this.responseText;
                }
                console.log(this.responseText);
            } else {
                console.log("auth returned " + this.status + ": " + this.responseText);
            }
        }
    };

    xhr.open("POST", "{{.auth_ep}}");
    xhr.send(JSON.stringify(o));

    return false;
}

function doMfa() {
    let o = {
        mfa_code: document.getElementById("mfa").value,
        type: document.getElementById("mfa-type").value
    };
    console.log(JSON.stringify(o));

    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        if (this.readyState === 4) {
            if (this.status === 200) {
                document.getElementById("mfa-modal").style.display = 'none';
                document.getElementById("mfa").value = "";
            } else if (this.status === 401) {
                document.getElementById("mfa-message").innerText = "Invalid MFA Code";
                document.getElementById("mfa").value = "";
                document.getElementById("mfa").focus();
                console.log(this.responseText);
            } else {
                console.log("auth returned " + this.status + ": " + this.responseText);
            }
        }
    };

    xhr.open("POST", "{{.auth_ep}}");
    xhr.send(JSON.stringify(o));

    return false;
}

window.addEventListener("load", function () {
    refreshRoles();
    selectRole();
});
`))
