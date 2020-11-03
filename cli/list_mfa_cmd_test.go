package cli

import (
	"flag"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/awstesting/mock"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/identity"
	"github.com/urfave/cli/v2"
	"os"
	"testing"
)

func TestListMfaCmd_Action(t *testing.T) {
	configResolver = new(mockConfigResolver)
	ctx := cli.NewContext(App, new(flag.FlagSet), nil)

	t.Run("saml", func(t *testing.T) {
		_ = os.Setenv("AWS_PROFILE", "saml")
		defer os.Unsetenv("AWS_PROFILE")

		if err := mfaCmd.Run(ctx); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("oidc", func(t *testing.T) {
		_ = os.Setenv("AWS_PROFILE", "oidc")
		defer os.Unsetenv("AWS_PROFILE")

		if err := mfaCmd.Run(ctx); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestListMfaCmd_sessionOptions(t *testing.T) {
	cfg := &config.AwsConfig{Region: "mock", ProfileName: "p", SrcProfile: "sp"}
	o := sessionOptions(cfg)

	if o.SharedConfigState != session.SharedConfigEnable {
		t.Error("shared config state was not enabled")
	}

	if o.Profile != cfg.SrcProfile {
		t.Error("profile mismatch")
	}

	if *o.Config.Region != cfg.Region {
		t.Error("region mismatch")
	}
}

func TestListMfaCmd_getIdentity(t *testing.T) {
	cfg := &config.AwsConfig{
		SamlUrl:      "http://mock.local/saml",
		SamlUsername: "mockUser",
		SamlProvider: "mock",
	}

	if _, err := getIdentity(cfg); err != nil {
		t.Error(err)
	}
}

func TestListMfaCmd_listMfa(t *testing.T) {
	t.Run("user", func(t *testing.T) {
		s := mock.Session
		s.Config.Region = aws.String("mock")
		listMfa(iam.New(s), &identity.Identity{IdentityType: "user"})
	})

	t.Run("not user", func(t *testing.T) {
		if err := listMfa(nil, &identity.Identity{IdentityType: "notuser"}); err != nil {
			t.Error(err)
		}
	})
}
