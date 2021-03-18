/*
 * Copyright (c) 2021 Michael Morris. All Rights Reserved.
 *
 * Licensed under the MIT license (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * https://github.com/mmmorris1975/aws-runas/blob/master/LICENSE
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under the License.
 */

package cli

import (
	"flag"
	"fmt"
	"github.com/urfave/cli/v2"
	"strconv"
)

var vFlag = &verboseFlag{
	Name:        "verbose",
	Aliases:     []string{"v"},
	Usage:       "output debug logging, use twice for AWS call tracing",
	Required:    false,
	Hidden:      false,
	Value:       new(boolSlice),
	DefaultText: "standard logging",
}

// It seems that only a Value type of bool will cause the help messaging to indicate that no value is required,
// regardless of the setting of IsBoolFlag() in the Value type, or GetValue() or TakesValue() in the flag.
// It's sort of annoying, but we'll live with it.
type verboseFlag struct {
	Name        string
	Aliases     []string
	Usage       string
	Required    bool
	Hidden      bool
	Value       *boolSlice
	DefaultText string
}

func (f *verboseFlag) IsRequired() bool {
	return f.Required
}

func (f *verboseFlag) String() string {
	return cli.FlagStringer(f)
}

func (f *verboseFlag) Apply(set *flag.FlagSet) error {
	for _, name := range f.Names() {
		set.Var(f.Value, name, f.Usage)
	}
	return nil
}

func (f *verboseFlag) Names() []string {
	names := []string{f.Name}
	return append(names, f.Aliases...)
}

func (f *verboseFlag) IsSet() bool {
	if f.Value != nil && len(f.Value.val) > 0 {
		return true
	}
	return false
}

func (f *verboseFlag) GetUsage() string {
	return f.Usage
}

// This apparently has no effect when displaying the help text (only when writing man or markdown formats).
func (f *verboseFlag) TakesValue() bool {
	return false
}

func (f *verboseFlag) GetValue() string {
	if f.Value != nil {
		return f.Value.String()
	}
	return ""
}

type boolSlice struct {
	val []bool
}

func (a *boolSlice) String() string {
	if a.val == nil {
		a.val = make([]bool, 0)
	}
	return fmt.Sprintf("%v", a.val)
}

func (a *boolSlice) Set(s string) error {
	if a.val == nil {
		a.val = make([]bool, 0)
	}

	b, _ := strconv.ParseBool(s)
	if b {
		a.val = append(a.val, b)
	}

	return nil
}

func (a *boolSlice) Get() interface{} {
	return a.val
}

func (a *boolSlice) IsBoolFlag() bool {
	return true
}
