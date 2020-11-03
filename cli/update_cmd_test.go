package cli

import (
	"flag"
	"github.com/urfave/cli/v2"
	"testing"
)

func TestUpdateCmd_Action(t *testing.T) {
	ctx := cli.NewContext(App, new(flag.FlagSet), nil)
	if err := updateCmd.Run(ctx); err != nil {
		t.Error(err)
	}
}
