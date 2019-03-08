package metadata

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/gorilla/websocket"
	"github.com/mmmorris1975/aws-runas/lib/config"
	credlib "github.com/mmmorris1975/aws-runas/lib/credentials"
	"github.com/mmmorris1975/simple-logger"
	"html/template"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	// EC2MetadataIp is the address used to contact the metadata service, per AWS
	EC2MetadataIp = "169.254.169.254"
	// EC2MetadataCredentialPath is the base path for instance role credentials in the metadata service
	EC2MetadataCredentialPath = "/latest/meta-data/iam/security-credentials/"
	// ListRolePath is the http server path to list the configured roles
	ListRolePath = "/list-roles"
	// MfaPath is the websocket endpoint for using MFA
	MfaPath = "/mfa"
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
	u   = websocket.Upgrader{}
)

func init() {
	EC2MetadataAddress, _ = net.ResolveIPAddr("ip", EC2MetadataIp)
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
	http.HandleFunc(EC2MetadataCredentialPath, credHandler)

	hp := net.JoinHostPort(EC2MetadataAddress.String(), "80")
	log.Infof("EC2 Metadata Service ready on %s", hp)
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

func homeHandler(w http.ResponseWriter, r *http.Request) {
	d := make(map[string]interface{})
	d["url"] = fmt.Sprintf("ws://%s%s", r.Host, MfaPath)
	d["roles"] = cfg.ListProfiles(true)
	homeTemplate.Execute(w, d)
}

func mfaHandler(w http.ResponseWriter, r *http.Request) {
	c, err := u.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("upgrade: %v", err)
		return
	}
	defer c.Close()

	for {
		mt, d, err := c.ReadMessage()
		if err != nil {
			log.Errorf("ReadMessage: %v", err)
			break
		}

		profile = string(d)
		p, err := cfg.ResolveConfig(profile)
		if err != nil {
			log.Errorf("ResolveConfig: %v", err)
			break
		}

		if role == nil || p.SourceProfile != role.SourceProfile {
			updateSession(p.SourceProfile)
			cred = credlib.NewSessionCredentials(s, func(pv *credlib.SessionTokenProvider) {
				//p.Cache = FileCredentialCache
				pv.Duration = p.SessionDuration
				pv.SerialNumber = p.MfaSerial
				pv.TokenProvider = func() (string, error) {
					c.WriteMessage(mt, []byte("Enter MFA Code"))
					_, d, err := c.ReadMessage()
					if err != nil {
						return "", err
					}
					log.Infof("MFA: %s", d)
					return string(d), nil
				}
			})
		}
		role = p

		cred.Get()
	}
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
		// return name of active role
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(profile))
		log.Infof("%s %d %d", r.URL.Path, http.StatusOK, len(profile))
	} else {
		// get the creds for the role
		b, err := assumeRole()
		if err != nil {
			log.Errorf("AssumeRole: %v", err)
			http.Error(w, "Error fetching role credentials", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write(b)
		log.Infof("%s %d %d", r.URL.Path, http.StatusOK, len(b))
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

	// 901 seconds is the absolute minimum Expiration time so that the default awscli logic won't think
	// our credentials are expired, and send a duplicate request.
	output := ec2MetadataOutput{
		Code:            "Success",
		LastUpdated:     time.Now().UTC().Format(time.RFC3339),
		Type:            "AWS-HMAC",
		AccessKeyId:     v.AccessKeyID,
		SecretAccessKey: v.SecretAccessKey,
		Token:           v.SessionToken,
		Expiration:      time.Now().Add(901 * time.Second).UTC().Format(time.RFC3339),
	}
	log.Debugf("%+v", output)

	j, err := json.Marshal(output)
	if err != nil {
		return nil, err
	}

	return j, nil
}

var homeTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<script>
window.addEventListener("load", function(evt) {
  var ws = new WebSocket("{{.url}}");

  ws.onclose = function(evt) {
    ws = null;
  };

  ws.onmessage = function(evt) {
    if (evt.data == "Enter MFA Code") {
      var mfa = prompt(evt.data, "");
      ws.send(mfa)
    } else {
      print("RESPONSE: " + evt.data);
    }
  };

  ws.onerror = function(evt) {
    // todo
    //print("ERROR: " + evt.data);
  };

  document.getElementById("roles").onchange = function(evt) {
    if (!ws) {
      return false;
    }

    ws.send(evt.target.value);
    return false;
  };

  document.getElementById("refresh").onclick = function(evt) {
    if (!ws) {
      return false;
    }

    return false;
  };
});
</script>
</head>
<body>
<form>
<select id="roles" name="roles">
{{range $e := .roles}}
  <option>{{$e}}</option>
{{end}}
</select>
<button id="refresh" name="refresh">Refresh MFA</button>
</form>
</body>
</html>
`))
