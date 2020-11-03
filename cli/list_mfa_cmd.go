package cli

import (
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/identity"
	"github.com/urfave/cli/v2"
	"strings"
)

var mfaCmd = &cli.Command{
	Name:      "mfa",
	Usage:     mfaFlag.Usage,
	ArgsUsage: "[profile_name]",

	BashComplete: bashCompleteProfile,

	Action: func(ctx *cli.Context) error {
		_, cfg, err := resolveConfig(ctx, 1)
		if err != nil {
			return err
		}

		if arn.IsARN(cfg.ProfileName) {
			return errors.New("profile looks like an ARN, check command parameters and environment variables")
		}

		if len(cfg.SamlUrl) > 0 || len(cfg.WebIdentityUrl) > 0 {
			return errors.New("detected SAML or Web Identity profile, only IAM profiles support MFA device retrieval")
		}

		// we know identity will be an IAM principal here
		id, err := getIdentity(cfg)
		if err != nil {
			return err
		}

		s := session.Must(session.NewSessionWithOptions(sessionOptions(cfg)))
		return listMfa(iam.New(s), id)
	},
}

// possibly reusable? may only be used with mfa lookup, since it should be the only place we need a hand-rolled
// session. All others should(?) be relying on the client factory
func sessionOptions(cfg *config.AwsConfig) session.Options {
	return session.Options{
		SharedConfigState: session.SharedConfigEnable,

		// we may want to eventually incorporate this to the client factory session options setup?
		Profile: func() string {
			profile := cfg.ProfileName
			if len(cfg.SrcProfile) > 0 {
				profile = cfg.SrcProfile
			}

			if strings.EqualFold(profile, session.DefaultSharedConfigProfile) {
				// Don't set Profile in options if it's the default value.
				// See release notes for v1.22.0 of the AWS SDK for the rationale
				return ""
			}
			return profile
		}(),

		Config: *new(aws.Config).
			WithRegion(cfg.Region).WithCredentialsChainVerboseErrors(true).
			WithLogLevel(opts.AwsLogLevel).
			WithLogger(aws.LoggerFunc(func(i ...interface{}) {
				log.Debug(i...)
			})),
	}
}

// mfa command-specific? really just to wrap multiple error paths to a single return value
func getIdentity(cfg *config.AwsConfig) (*identity.Identity, error) {
	c, err := clientFactory.Get(cfg)
	if err != nil {
		return nil, err
	}

	return c.Identity()
}

// mfa command-specific, but set as a distinct function so it's testable with a mock iamiface.IAMAPI
func listMfa(i iamiface.IAMAPI, id *identity.Identity) error {
	if id.IdentityType == "user" {
		res, err := i.ListMFADevices(new(iam.ListMFADevicesInput))
		if err != nil {
			return err
		}

		for _, d := range res.MFADevices {
			fmt.Println(*d.SerialNumber)
		}
	}
	return nil
}
