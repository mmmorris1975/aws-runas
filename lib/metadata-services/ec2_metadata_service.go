package metadata_services

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/mbndr/logo"
	"github.com/mmmorris1975/aws-runas/lib"
	"net"
	"net/http"
	"os"
	"time"
)

const EC2_METADATA_CREDENTIAL_PATH = "/latest/meta-data/iam/security-credentials/"

type EC2MetadataOutput struct {
	Code            string
	LastUpdated     string
	Type            string
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      string
}

func NewEC2MetadataService(profile *lib.AWSProfile, options *lib.CachedCredentialsProviderOptions) error {
	log := logo.NewSimpleLogger(os.Stderr, options.LogLevel, "aws-runas.EC2MetadataService", true)
	addr := EC2MetadataAddress

	lo, err := discoverLoopback()
	if err != nil {
		return err
	}
	log.Debugf("LOOPBACK INTERFACE: %s", lo)

	if err := addAddress(lo, addr); err != nil {
		return err
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
		output := EC2MetadataOutput{
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
