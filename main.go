package main

import (
	"github.com/mmmorris1975/aws-runas/cli"
	"log"
	"os"
)

// Version is managed at compile-time.
var Version = "0.0.0"

func main() {
	cli.App.Version = Version
	if err := cli.App.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
