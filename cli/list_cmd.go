package cli

import (
	"github.com/urfave/cli/v2"
)

var listCmd = &cli.Command{
	Name:        "list",
	Aliases:     []string{"ls"},
	Usage:       "Shows IAM roles or MFA device configuration",
	ArgsUsage:   " ", // this hides the default '[arguments...]' help text output, since we don't use command args here
	Subcommands: []*cli.Command{mfaCmd, rolesCmd},
}
