package cli

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/credentials/helpers"
	"github.com/urfave/cli/v2"
	"gopkg.in/ini.v1"
	"io/ioutil"
	"os"
)

const passwordDesc = `Manage the password for the external identity provider (SAML or OIDC) in the .aws/credentials
   file.  The entry is keyed off of the URL configured for the specified 'profile_name' so it
   can be shared across multiple profiles.  The password is obfuscated (not encrypted!) to avoid
   storing the plaintext value in the file.`

var passwordCmd = &cli.Command{
	Name:        "password",
	Aliases:     []string{"passwd", "pw"},
	Usage:       "Set or update the stored password for an external identity provider",
	ArgsUsage:   "profile_name",
	Description: passwordDesc,

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
	key := "saml_password"
	if len(cfg.WebIdentityUrl) > 0 {
		url = cfg.WebIdentityUrl
		key = "web_identity_password"
	}

	crypt, err := helpers.NewPasswordEncoder([]byte(url)).Encode(password, 18)
	if err != nil {
		return err
	}

	src := defaults.SharedCredentialsFilename()
	if v, ok := os.LookupEnv("AWS_SHARED_CREDENTIALS_FILE"); ok {
		src = v
	}

	f, err := ini.Load(src)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		newFile, err := os.Create(src)
		if err != nil {
			return err
		}

		f, err = ini.Load(newFile)
	}
	f.Section(url).Key(key).SetValue(crypt)

	return writeOutput(f, src)
}

func writeOutput(f *ini.File, dst string) error {
	tmp, err := ioutil.TempFile("", "aws-runas-credentials-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	log.Debug("saving credentials")
	if err = f.SaveTo(tmp.Name()); err != nil {
		return err
	}
	_ = tmp.Close()

	if err = os.Rename(tmp.Name(), dst); err != nil {
		return err
	}
	_ = os.Chmod(dst, 0600)
	return nil
}
