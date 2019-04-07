package metadata

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/mmmorris1975/aws-runas/lib/config"
	credlib "github.com/mmmorris1975/aws-runas/lib/credentials"
	"github.com/mmmorris1975/simple-logger"
	"html/template"
	"io"
	"net"
	"net/http"
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

	profile string
	role    *config.AwsConfig
	cfg     config.ConfigResolver
	s       *session.Session
	cred    *credentials.Credentials
	usr     *credlib.AwsIdentity

	log = simple_logger.StdLogger
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

// NewEC2MetadataService starts an HTTP server which will listen on the EC2 metadata service path for handling
// requests for instance role credentials.  SDKs will first look up the path in EC2MetadataCredentialPath,
// which returns the name of the instance role in use, it then appends that value to the previous request url
// and expects the response body to contain the credential data in json format.
func NewEC2MetadataService(logLevel uint) error {
	log.SetLevel(logLevel)
	cf, err := config.NewConfigResolver(nil)
	if err != nil {
		return err
	}
	cfg = cf.WithLogger(log)

	lo, err := setupInterface()
	if err != nil {
		return err
	}
	defer removeAddress(lo, EC2MetadataAddress)

	http.HandleFunc("/", homeHandler)
	http.HandleFunc(MfaPath, mfaHandler)
	http.HandleFunc(ProfilePath, profileHandler)
	http.HandleFunc(EC2MetadataCredentialPath, credHandler)
	http.HandleFunc(ListRolesPath, listRoleHandler)
	http.HandleFunc(RefreshPath, refreshHandler)

	hp := net.JoinHostPort(EC2MetadataAddress.String(), "80")
	log.Infof("EC2 Metadata Service ready on http://%s", hp)
	return http.ListenAndServe(hp, nil)
}

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
			updateSession(p.SourceProfile)
			cred = credlib.NewSessionCredentials(s, func(pv *credlib.SessionTokenProvider) {
				pv.Duration = p.SessionDuration
				pv.SerialNumber = p.MfaSerial
			})
		}
		role = p

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
	sc := new(aws.Config).WithCredentialsChainVerboseErrors(true).WithLogger(log)
	if log.Level == simple_logger.DEBUG {
		sc.LogLevel = aws.LogLevel(aws.LogDebug)
	}
	o := session.Options{Config: *sc, Profile: p}
	s = session.Must(session.NewSessionWithOptions(o))

	usr, err = credlib.NewAwsIdentityManager(s).WithLogger(log).GetCallerIdentity()
	if err != nil {
		return err
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
	}
	writeResponse(w, r, "success", http.StatusOK)
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

window.addEventListener("load", function(evt) {
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
  background-color: purple;
  font-family: Tahoma, Geneva, sans-serif;
  font-size: large;
  margin: 0;
}

#content {
  background-color: white;
  margin: auto;
  width: 30em;
  padding: 0.5em;
  padding-top: 1.2em;
}

#message {
  margin-top: 0.5em;
}
</style>
</head>
<body>
<div id="content">
<form>
<div>
<label for="roles">Roles</label>&nbsp;
<select id="roles" name="roles">
  <option value="">-- Select Role--</option>
{{range $e := .roles}}
  <option>{{$e}}</option>
{{end}}
</select>
</div>
<div>
<div id="message">&nbsp;</div>
<button id="refresh" name="refresh">Refresh Now</button>
</div>
</form>
</div>
</body>
</html>
`))
