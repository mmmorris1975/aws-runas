package cli

import (
	"context"
	"errors"
	"flag"
	"github.com/aws/aws-sdk-go-v2/service/iam"
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

	t.Run("arn", func(t *testing.T) {
		_ = os.Setenv("AWS_PROFILE", "arn:aws:iam::0123456789:role/my_role")
		defer os.Unsetenv("AWS_PROFILE")

		if err := mfaCmd.Run(ctx); err == nil {
			t.Error("did not receive expected error")
		}
	})
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
		_ = listMfa(new(mockIam), &identity.Identity{IdentityType: "user"})
	})

	t.Run("not user", func(t *testing.T) {
		if err := listMfa(nil, &identity.Identity{IdentityType: "notuser"}); err != nil {
			t.Error(err)
		}
	})

	t.Run("bad", func(t *testing.T) {
		var c mockIam = true
		if err := listMfa(&c, &identity.Identity{IdentityType: "user"}); err == nil {
			t.Error(err)
		}
	})
}

type mockIam bool

func (m *mockIam) ListMFADevices(ctx context.Context, in *iam.ListMFADevicesInput, opts ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	if *m {
		return nil, errors.New("failed")
	}

	return new(iam.ListMFADevicesOutput), nil
}
