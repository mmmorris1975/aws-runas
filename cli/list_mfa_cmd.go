/*
 * Copyright (c) 2021 Michael Morris. All Rights Reserved.
 *
 * Licensed under the MIT license (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * https://github.com/mmmorris1975/aws-runas/blob/master/LICENSE
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under the License.
 */

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
		id, err := getIdentity(ctx.Context, cfg)
		if err != nil {
			return err
		}

		s, err := awsconfig.LoadDefaultConfig(ctx.Context,
			awsconfig.WithLogger(logFunc),
			awsconfig.WithRegion(cfg.Region),
			awsconfig.WithSharedConfigProfile(getSharedProfile(cfg)),
		)
		if err != nil {
			return err
		}
		return listMfa(ctx.Context, iam.NewFromConfig(s), id)
	},
}

func getSharedProfile(cfg *config.AwsConfig) string {
	profile := cfg.ProfileName
	if len(cfg.SrcProfile) > 0 {
		profile = cfg.SrcProfile
	}
	return profile
}

// mfa command-specific? really just to wrap multiple error paths to a single return value.
func getIdentity(ctx context.Context, cfg *config.AwsConfig) (*identity.Identity, error) {
	c, err := clientFactory.Get(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return c.IdentityWithContext(ctx)
}

// mfa command-specific, but use a distinct function so it's testable with a mock iam.ListMFADevicesAPIClient.
func listMfa(ctx context.Context, i iam.ListMFADevicesAPIClient, id *identity.Identity) error {
	if id.IdentityType == "user" {
		res, err := i.ListMFADevices(ctx, new(iam.ListMFADevicesInput))
		if err != nil {
			return err
		}

		for _, d := range res.MFADevices {
			fmt.Println(*d.SerialNumber)
		}
	}
	return nil
}
