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
	"errors"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/credentials/helpers"
	"github.com/urfave/cli/v2"
	"os"
)

const passwordDesc = `Manage the password for the external identity provider (SAML or OIDC) in the .aws/credentials
file.  The entry is keyed off of the URL configured for the specified 'profile_name' so it
can be shared across multiple profiles.  The password is obfuscated (not encrypted!) to avoid
storing the plaintext value in the file.`

var passwordCmd = &cli.Command{
	Name:         "password",
	Aliases:      []string{"passwd", "pw"},
	Usage:        "Set or update the stored password for an external identity provider",
	ArgsUsage:    "profile_name",
	Description:  passwordDesc,
	BashComplete: bashCompleteProfile,

	Action: func(ctx *cli.Context) error {
		_, cfg, err := resolveConfig(ctx, 1)
		if err != nil {
			return err
		}

		pw, err := validateInput(cfg)
		if err != nil {
			return err
		}

		return updateCreds(cfg, pw)
	},
}

func validateInput(cfg *config.AwsConfig) (string, error) {
	if len(cfg.SamlUrl) < 1 && len(cfg.WebIdentityUrl) < 1 {
		return "", errors.New("external identity provider not set, must configure either saml_auth_url or web_identity_auth_url")
	}

	if len(cfg.SamlUrl) > 0 && len(cfg.WebIdentityUrl) > 0 {
		return "", errors.New("detected both SAML and Web Identity (OIDC) URLs, only 1 allowed")
	}

	password := cmdlineCreds.SamlPassword
	if len(cfg.WebIdentityUrl) > 0 {
		password = cmdlineCreds.WebIdentityPassword
	}

	if len(password) < 1 {
		_, pw, err := helpers.NewUserPasswordInputProvider(os.Stdin).ReadInput("nouser", "")
		if err != nil {
			return "", err
		}
		password = pw
	}

	return password, nil
}

func updateCreds(cfg *config.AwsConfig, password string) error {
	url := cfg.SamlUrl
	if len(cfg.WebIdentityUrl) > 0 {
		url = cfg.WebIdentityUrl
	}

	crypt, err := helpers.NewPasswordEncoder([]byte(url)).Encode(password, 18)
	if err != nil {
		return err
	}

	creds := new(config.AwsCredentials)
	if len(cfg.WebIdentityUrl) > 0 {
		creds.WebIdentityPassword = crypt
	} else {
		creds.SamlPassword = crypt
	}

	return config.DefaultIniLoader.SaveCredentials(url, creds)
}
