package metadata

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/mmmorris1975/aws-runas/lib/cache"
	"github.com/mmmorris1975/aws-runas/lib/config"
	credlib "github.com/mmmorris1975/aws-runas/lib/credentials"
	"github.com/mmmorris1975/simple-logger"
	"golang.org/x/sys/unix"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	// EC2MetadataIp is the address used to contact the metadata service, per AWS
	EC2MetadataIp = "169.254.169.254"
	// EC2MetadataCredentialPath is the base path for instance role credentials in the metadata service
	EC2MetadataCredentialPath = "/latest/meta-data/iam/security-credentials/"
	// MfaPath is the websocket endpoint for using MFA
	MfaPath = "/mfa"
	// ProfilePath is the endpoint for getting/setting the profile to use
	ProfilePath = "/profile"
	// ListProfilePath is the endpoint for listing all known roles
	ListRolesPath = "/list-roles"
	// RefreshPath is the endpoint for forcing a credential refresh
	RefreshPath = "/refresh"
)

var (
	// EC2MetadataAddress is the net.IPAddr of the EC2 metadata service
	EC2MetadataAddress *net.IPAddr

	profile  string
	role     *config.AwsConfig
	cfg      config.ConfigResolver
	s        *session.Session
	cred     *credentials.Credentials
	usr      *credlib.AwsIdentity
	log      *simple_logger.Logger
	cacheDir string
)

func init() {
	EC2MetadataAddress, _ = net.ResolveIPAddr("ip", EC2MetadataIp)
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
	LastUpdated     string
	Type            string
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      string
}

type EC2MetadataInput struct {
	Config          *config.AwsConfig
	InitialProfile  string
	Logger          *simple_logger.Logger
	Session         *session.Session
	SessionCacheDir string
	User            *credlib.AwsIdentity
}

// NewEC2MetadataService starts an HTTP server which will listen on the EC2 metadata service path for handling
// requests for instance role credentials.  SDKs will first look up the path in EC2MetadataCredentialPath,
// which returns the name of the instance role in use, it then appends that value to the previous request url
// and expects the response body to contain the credential data in json format.
func NewEC2MetadataService(opts *EC2MetadataInput) error {
	if err := handleOptions(opts); err != nil {
		return err
	}

	lo, err := setupInterface()
	if err != nil {
		return err
	}
	defer func() {
		if err := removeAddress(lo, EC2MetadataAddress); err != nil {
			log.Debugf("Error removing network config: %v", err)
		}
	}()

	hp := net.JoinHostPort(EC2MetadataAddress.String(), "80")
	l, err := net.Listen("tcp4", hp)
	if err != nil {
		log.Fatalf("Error creating listener: %v", err)
	}

	if err := dropPrivileges(); err != nil {
		log.Fatalf("Error dropping privileges, will not continue: %v", err)
	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc(MfaPath, mfaHandler)
	http.HandleFunc(ProfilePath, profileHandler)
	http.HandleFunc(EC2MetadataCredentialPath, credHandler)
	http.HandleFunc(ListRolesPath, listRoleHandler)
	http.HandleFunc(RefreshPath, refreshHandler)

	msg := fmt.Sprintf("EC2 Metadata Service ready on http://%s", hp)
	if len(profile) < 1 {
		msg = msg + " without an initial profile, set one via the web interface"
	} else {
		msg = msg + fmt.Sprintf(" using initial profile '%s'", profile)
	}

	log.Infof(msg)
	return http.Serve(l, nil)
}

func handleOptions(opts *EC2MetadataInput) error {
	log = opts.Logger
	if log == nil {
		log = simple_logger.StdLogger
	}

	s = opts.Session
	usr = opts.User
	role = opts.Config
	profile = opts.InitialProfile

	cacheDir = opts.SessionCacheDir
	if len(cacheDir) < 1 {
		d, err := os.UserCacheDir()
		if err != nil {
			log.Debugf("Error finding User Cache Dir: %v", err)
		}
		cacheDir = d
	}

	cf, err := config.NewConfigResolver(nil)
	if err != nil {
		return err
	}
	cfg = cf.WithLogger(log)

	return nil
}

// This is really the only semi-sane way to configure the necessary networking, it still requires
// admin/sudo privileges on the system, and relies on OS-specific commands under the covers.
// However, it avoids a bunch of other ugliness to make things work (iptables for linux, not
// sure about others ... maybe the route command? Regardless even those require admin/sudo)
func setupInterface() (string, error) {
	lo, err := discoverLoopback()
	if err != nil {
		return "", err
	}
	log.Debugf("LOOPBACK INTERFACE: %s", lo)

	if err := addAddress(lo, EC2MetadataAddress); err != nil {
		if err := removeAddress(lo, EC2MetadataAddress); err != nil {
			return "", err
		}

		if err := addAddress(lo, EC2MetadataAddress); err != nil {
			return "", err
		}
	}
	return lo, err
}

func dropPrivileges() (err error) {
	// precedence list (1st one wins)
	// 1. SUDO_UID and SUDO_GID env vars
	// 2. ownership of cacheDir
	// 3. ownership of HOME env var (the pre-sudo value is retained) ... obtained via os.UserHomeDir()
	if runtime.GOOS != "windows" {
		// making a bold assumption that anything non-Windows supports what we're doing ... this is probably buggy as hell
		var uid int
		var gid int

		uid, gid, err := checkSudoEnv()
		if err != nil {
			// fall through
			log.Debugf("Error checking sudo env vars: %v", err)
		} else {
			log.Debugf("Found UID/GID from sudo env vars: UID: %d, GID: %d", uid, gid)
			return setPrivileges(uid, gid)
		}

		uid, gid, err = stat(cacheDir)
		if err != nil {
			// fall through
			log.Debugf("Error checking cache directory: %v", err)
		} else {
			log.Debugf("Found UID/GID from cache directory ownership: UID: %d, GID: %d", uid, gid)
			return setPrivileges(uid, gid)
		}

		// Last option for getting pre-sudo uid/gid, fail if we see an error
		uid, gid, err = statHomeDir()
		if err != nil {
			log.Debugf("Error checking home directory: %v", err)
			return err
		} else {
			log.Debugf("Found UID/GID from home directory ownership: UID: %d, GID: %d", uid, gid)
			return setPrivileges(uid, gid)
		}
	}
	return nil
}

func checkSudoEnv() (int, int, error) {
	u, uok := os.LookupEnv("SUDO_UID")
	g, gok := os.LookupEnv("SUDO_GID")
	if uok && gok {
		uid, err := strconv.Atoi(u)
		if err != nil {
			return -1, -1, err
		}

		gid, err := strconv.Atoi(g)
		if err != nil {
			return -1, -1, err
		}

		return uid, gid, nil
	}
	return -1, -1, fmt.Errorf("sudo environment variables not found")
}

func statHomeDir() (int, int, error) {
	h, err := os.UserHomeDir() // added in Go 1.12
	if err != nil {
		return -1, -1, err
	}
	return stat(h)
}

func stat(path string) (int, int, error) {
	if len(path) > 0 {
		st := new(unix.Stat_t)
		if err := unix.Stat(path, st); err != nil {
			// Whatever -1 will mean on the platform will certainly be better than returning 0 for the uid/gid values!
			return -1, -1, err
		}
		return int(st.Uid), int(st.Gid), nil
	}
	return -1, -1, fmt.Errorf("stat(): empty path")
}

func setPrivileges(uid int, gid int) error {
	// REF: https://wiki.sei.cmu.edu/confluence/display/c/POS36-C.+Observe+correct+revocation+order+while+relinquishing+privileges
	if err := unix.Setgid(gid); err != nil {
		return err
	}

	if err := unix.Setuid(uid); err != nil {
		return err
	}
	return nil
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
	w.WriteHeader(code)
	if _, err := w.Write([]byte(body)); err != nil {
		log.Error(err)
	}

	log.Infof("%s %s %s %d %s", r.Method, r.URL.Path, r.Proto, code, contentLength)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	d := make(map[string]interface{})
	d["roles"] = listRoles()
	d["profile_ep"] = ProfilePath
	d["mfa_ep"] = MfaPath
	d["refresh_ep"] = RefreshPath

	b := new(strings.Builder)
	if err := homeTemplate.Execute(b, d); err != nil {
		log.Error(err)
		writeResponse(w, r, "Error building content", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	writeResponse(w, r, b.String(), http.StatusOK)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		p, hErr := getProfileConfig(r.Body)
		if hErr != nil {
			writeResponse(w, r, hErr.Error(), hErr.code)
			return
		}
		log.Debugf("retrieved profile %+v", p)

		if role == nil || p.SourceProfile != role.SourceProfile {
			if err := updateSession(p.SourceProfile); err != nil {
				log.Debugf("error updating session: %v", err)
			}
		}

		role = p
		cred = credlib.NewSessionCredentials(s, func(pv *credlib.SessionTokenProvider) {
			pv.Duration = role.SessionDuration
			pv.SerialNumber = role.MfaSerial

			cf := cacheFile(role.SourceProfile)
			if len(cf) > 0 {
				pv.Cache = &cache.FileCredentialCache{Path: cf}
			}
		})

		_, err := cred.Get()
		if err != nil {
			switch t := err.(type) {
			case *credlib.ErrMfaRequired:
				writeResponse(w, r, "MFA code required", http.StatusUnauthorized)
				return
			case awserr.Error:
				if t.Code() == "AccessDenied" && strings.HasPrefix(t.Message(), "MultiFactorAuthentication failed") {
					writeResponse(w, r, "MFA code required", http.StatusUnauthorized)
					return
				}
			}

			log.Error(err)
			writeResponse(w, r, "Error getting session credentials", http.StatusInternalServerError)
			return
		}

		t, _ := cred.ExpiresAt()
		writeResponse(w, r, t.Local().String(), http.StatusOK)
	} else {
		sendProfile(w, r)
	}
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

	profile = string(b[:n])
	p, err := cfg.ResolveConfig(profile)
	if err != nil {
		log.Error(err)
		return nil, newHandlerError("Error resolving profile config", http.StatusInternalServerError)
	}

	return p, nil
}

func sendProfile(w http.ResponseWriter, r *http.Request) {
	// return name of active role
	writeResponse(w, r, profile, http.StatusOK)
}

func mfaHandler(w http.ResponseWriter, r *http.Request) {
	mfa, err := getMfa(r.Body)
	if err != nil {
		writeResponse(w, r, err.Error(), err.code)
		return
	}

	cred = credlib.NewSessionCredentials(s, func(pv *credlib.SessionTokenProvider) {
		pv.Duration = role.SessionDuration
		pv.SerialNumber = role.MfaSerial
		pv.TokenCode = mfa

		cf := cacheFile(role.SourceProfile)
		if len(cf) > 0 {
			pv.Cache = &cache.FileCredentialCache{Path: cf}
		}
	})

	if _, err := cred.Get(); err != nil {
		log.Error(err)
		writeResponse(w, r, "Error getting session credentials", http.StatusInternalServerError)
		return
	}

	t, _ := cred.ExpiresAt()
	writeResponse(w, r, t.Local().String(), http.StatusOK)
}

func getMfa(r io.Reader) (string, *handlerError) {
	if r == nil {
		return "", newHandlerError("nil reader", http.StatusInternalServerError)
	}

	mfaLen := 6
	b := make([]byte, 64)

	n, err := r.Read(b)
	if err != nil && err != io.EOF {
		log.Error(err)
		return "", newHandlerError("Error reading request data", http.StatusInternalServerError)
	}

	// AWS says MFA code must be exactly 6 bytes, check for < 6 condition here and truncate the
	// supplied code string to 6 bytes down below. Return HTTP Unauthorized (401), so we re-prompt
	if n < mfaLen {
		return "", newHandlerError("Invalid MFA Code", http.StatusUnauthorized)
	}

	return string(b[:mfaLen]), nil
}

func updateSession(p string) (err error) {
	var sc *aws.Config
	if s != nil {
		sc = s.Config
	} else {
		sc = new(aws.Config).WithCredentialsChainVerboseErrors(true).WithLogger(log)
		if log.Level == simple_logger.DEBUG {
			sc.LogLevel = aws.LogLevel(aws.LogDebug)
		}
	}

	o := session.Options{Config: *sc, Profile: p}
	s = session.Must(session.NewSessionWithOptions(o))

	if usr == nil {
		usr, err = credlib.NewAwsIdentityManager(s).WithLogger(log).GetCallerIdentity()
		if err != nil {
			return err
		}
	}

	return nil
}

func credHandler(w http.ResponseWriter, r *http.Request) {
	p := strings.Split(r.URL.Path, "/")[1:]
	if len(p[len(p)-1]) < 1 {
		sendProfile(w, r)
	} else {
		// get the creds for the role
		b, err := assumeRole()
		if err != nil {
			log.Errorf("AssumeRole: %v", err)
			writeResponse(w, r, "Error getting role credentials", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		writeResponse(w, r, string(b), http.StatusOK)
	}
}

func assumeRole() ([]byte, error) {
	log.Debugf("ROLE ARN: %s", role.RoleArn)
	ar := credlib.NewAssumeRoleCredentials(s.Copy(new(aws.Config).WithCredentials(cred)), role.RoleArn, func(p *credlib.AssumeRoleProvider) {
		p.Duration = credlib.AssumeRoleDefaultDuration
		p.ExternalID = role.ExternalID
		p.RoleSessionName = usr.UserName
	})

	v, err := ar.Get()
	if err != nil {
		return nil, err
	}

	// 1 second more than the minimum Assume Role credential duration is the absolute minimum Expiration time so that
	// the default awscli logic won't think our credentials are expired, and send a duplicate request.
	output := ec2MetadataOutput{
		Code:            "Success",
		LastUpdated:     time.Now().UTC().Format(time.RFC3339),
		Type:            "AWS-HMAC",
		AccessKeyId:     v.AccessKeyID,
		SecretAccessKey: v.SecretAccessKey,
		Token:           v.SessionToken,
		Expiration:      time.Now().Add(credlib.AssumeRoleMinDuration).Add(1 * time.Second).UTC().Format(time.RFC3339),
	}
	log.Debugf("%+v", output)

	j, err := json.Marshal(output)
	if err != nil {
		return nil, err
	}

	return j, nil
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
	if cfg != nil {
		return cfg.ListProfiles(true)
	}
	return []string{}
}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && cred != nil {
		log.Debug("Expiring credentials for refresh")
		cred.Expire()

		if role != nil {
			cf := cacheFile(role.SourceProfile)
			if len(cf) > 0 {
				if err := os.Remove(cf); err != nil {
					log.Debugf("Error removing cached credentials: %v", err)
				}
			}
		}
	}
	writeResponse(w, r, "success", http.StatusOK)
}

func cacheFile(p string) string {
	if len(cacheDir) > 0 && len(p) > 0 {
		return filepath.Join(cacheDir, fmt.Sprintf(".aws_session_token_%s", p))
	}
	return ""
}

var homeTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>aws-runas - AWS Metadata Credential Server</title>
<script>
function postProfile(role) {
  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function() {
    if (this.readyState == 4) { 
      if (this.status == 200) {
        var data = this.responseText;
        document.getElementById("message").innerHTML = "Credentials will expire on <i>" + data + "</i>"
      } else if (this.status == 401) {
        var mfa = prompt("Enter MFA Code", "");
        this.open("POST", {{.mfa_ep}}, true);
        this.send(mfa);
      }
    }
  }

  xhr.open("POST", {{.profile_ep}}, true);
  xhr.send(role);
}

function selectRole() {
  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
      var role = this.responseText;
      var opts = document.getElementById("roles").options

      for (o in opts) {
        opt = opts[o]
        if (opt.text == role) {
          opt.selected = true;
          postProfile(role)
          break;
        } else {
          opts[0].selected = true;
        }
      }
    }
  }

  xhr.open("GET", {{.profile_ep}}, true);
  xhr.send();
  return false;
}

window.addEventListener("load", function(evt) {
  selectRole()

  document.getElementById("roles").onchange = function(evt) {
    postProfile(evt.target.value);
    return false;
  };

  document.getElementById("refresh").onclick = function(evt) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
      if (this.readyState == 4 && this.status == 200) {
        r = document.getElementById("roles")
        postProfile(r.options[r.selectedIndex].text);
      }
    }

    xhr.open("POST", {{.refresh_ep}}, true);
    xhr.send();
    return false;
  };
});
</script>
<style>
body {
  background-color: navy;
  font-family: Tahoma, Geneva, sans-serif;
  font-size: large;
  margin: 0;
}

#content {
  background-color: white;
  margin: auto;
  width: 30em;
  padding: 0.5em;
}

#message {
  margin-top: 1em;
}

#title {
  text-align: center;
}

#roles {
  font-size: large;
}

option {
  font-size: large;
}

#refresh {
  background-color: crimson;
  border: 2px solid crimson;
  color: white;
  padding: 0.5em 1em;
  font-weight: bold;
  font-size: large;
  text-align: center;
  text-decoration: none;
  display: inline-block;
  border-radius: 0.33em;
  margin-left: 3em;
}

#refresh:hover {
  background-color: white;
  border: 2px solid crimson;
  color: crimson;
}
</style>
</head>
<body>
<div id="content">
  <div id = "title">
  <h2>EC2 Metadata Service Role Selector</h2>
  </div>

  <div id="form">
  <form>
  <label for="roles"><b>Roles</b></label>&nbsp;
  <select id="roles" name="roles">
    <option value="">-- Select Role--</option>
{{range $e := .roles}}
    <option>{{$e}}</option>
{{end}}
  </select>
  <button id="refresh" name="refresh" title="Force a refresh of the credentials, may require re-entering MFA code">
    Refresh Now
  </button>
  </form>
  </div>

  <div id="message">&nbsp;</div>
</div>
</body>
</html>
`))
