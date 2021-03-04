package cli

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/identity"
	"github.com/urfave/cli/v2"
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

		s, err := awsconfig.LoadDefaultConfig(context.Background())
		if err != nil {
			return err
		}
		return listMfa(iam.NewFromConfig(s), id)
	},
}

// mfa command-specific? really just to wrap multiple error paths to a single return value.
func getIdentity(cfg *config.AwsConfig) (*identity.Identity, error) {
	c, err := clientFactory.Get(cfg)
	if err != nil {
		return nil, err
	}

	return c.Identity()
}

// mfa command-specific, but set as a distinct function so it's testable with a mock iamiface.IAMAPI.
func listMfa(i iam.ListMFADevicesAPIClient, id *identity.Identity) error {
	if id.IdentityType == "user" {
		res, err := i.ListMFADevices(context.Background(), new(iam.ListMFADevicesInput))
		if err != nil {
			return err
		}

		for _, d := range res.MFADevices {
			fmt.Println(*d.SerialNumber)
		}
	}
	return nil
}
