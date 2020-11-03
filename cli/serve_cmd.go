package cli

import "github.com/urfave/cli/v2"

var serveCmd = &cli.Command{
	Name:        "serve",
	Aliases:     []string{"srv"},
	Usage:       "Serve credentials from a listening HTTP service",
	ArgsUsage:   " ", // this hides the default '[arguments...]' help text output, since we don't use command args here
	Subcommands: []*cli.Command{ec2Cmd, ecsCmd},
}
