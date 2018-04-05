package main

import (
	"fmt"
	"gopkg.in/alecthomas/kingpin.v2"
)

type cmdArg []string

func (i *cmdArg) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func (i *cmdArg) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *cmdArg) IsCumulative() bool {
	return true
}

// A custom kingpin type which allows consumption of multiple values
// and treat them as a single value.  Used for consuming all remaining
// command-line arguments to treat as the full command to wrap and execute.
func CmdArg(s kingpin.Settings) (target *[]string) {
	target = new([]string)
	s.SetValue((*cmdArg)(target))
	return
}
