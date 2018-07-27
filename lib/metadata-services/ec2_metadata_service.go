package metadata_services

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/mmmorris1975/aws-runas/lib"
	"net"
	"net/http"
	"time"
)

// EC2_METADATA_CREDENTIAL_PATH - the base path for instance profile credentials in the metadata service
const EC2_METADATA_CREDENTIAL_PATH = "/latest/meta-data/iam/security-credentials/"

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
// requests for instance profile credentials.  SDKs will first look up the path in EC2_METADATA_CREDENTIAL_PATH,
// which returns the name of the instance profile in use, it then appends that value to the previous request url
// and expects the response body to contain the credential data in json format.
func NewEC2MetadataService(profile *lib.AWSProfile, options *lib.CachedCredentialsProviderOptions) error {
	log := lib.NewLogger("aws-runas.EC2MetadataService", options.LogLevel)
	addr := EC2MetadataAddress

	lo, err := discoverLoopback()
	if err != nil {
		return err
	}
	log.Debugf("LOOPBACK INTERFACE: %s", lo)

	if err := addAddress(lo, addr); err != nil {
		if err := removeAddress(lo, addr); err != nil {
			return err
		}

		if err := addAddress(lo, addr); err != nil {
			return err
		}
	}
	defer removeAddress(lo, addr)

	// Fetch credentials right away so if we need to refresh and do MFA it all
	// happens at the start, and caches the results
	c := credentials.NewCredentials(lib.NewAssumeRoleProvider(profile, options))
	c.Get()

	http.HandleFunc(EC2_METADATA_CREDENTIAL_PATH+profile.Name, func(writer http.ResponseWriter, request *http.Request) {
		v, err := c.Get()
		if err != nil {
			log.Errorf("AssumeRole(): %v", err)
			http.Error(writer, "Error fetching role credentials", http.StatusInternalServerError)
			return
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
			log.Errorf("json.Marshal(): %v", err)
			http.Error(writer, "Error marshalling credentials to json", http.StatusInternalServerError)
			return
		}

		writer.Header().Set("Content-Type", "text/plain")
		writer.Write(j)
		log.Infof("%s %d %d", request.URL.Path, http.StatusOK, len(j))
	})

	http.HandleFunc(EC2_METADATA_CREDENTIAL_PATH, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		writer.Write([]byte(profile.Name))
		log.Debugf("Returning profile name %s", profile.Name)
	})

	http.Handle("/", http.NotFoundHandler())

	return http.ListenAndServe(net.JoinHostPort(addr.String(), "80"), nil)
}
