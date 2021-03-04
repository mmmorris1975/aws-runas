package cli

import (
	"flag"
	"github.com/urfave/cli/v2"
	"testing"
)

func Test_doSsmSetup(t *testing.T) {
	configResolver = new(mockConfigResolver)
	ctx := cli.NewContext(App, new(flag.FlagSet), nil)

	_, _, err := doSsmSetup(ctx, 1)
	if err != nil {
		t.Error(err)
	}
}
