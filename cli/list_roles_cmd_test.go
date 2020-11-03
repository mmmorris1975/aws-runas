package cli

import (
	"flag"
	"github.com/urfave/cli/v2"
	"os"
	"testing"
)

func TestListRolesCmd_Action(t *testing.T) {
	configResolver = new(mockConfigResolver)
	ctx := cli.NewContext(App, new(flag.FlagSet), nil)

	t.Run("saml", func(t *testing.T) {
		_ = os.Setenv("AWS_PROFILE", "saml")
		defer os.Unsetenv("AWS_PROFILE")

		if err := rolesCmd.Run(ctx); err != nil {
			t.Error(err)
		}
	})

	t.Run("oidc", func(t *testing.T) {
		_ = os.Setenv("AWS_PROFILE", "oidc")
		defer os.Unsetenv("AWS_PROFILE")

		if err := rolesCmd.Run(ctx); err == nil {
			t.Error("did not receive expected error")
		}
	})
}
