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
	"context"
	"testing"

	"github.com/urfave/cli/v3"
)

func TestVerboseFlagCount(t *testing.T) {
	flag := newTestVerboseFlag()
	cmd := cli.Command{
		Name:                   t.Name(),
		UseShortOptionHandling: true,
		Flags:                  []cli.Flag{flag},
		Action: func(_ context.Context, c *cli.Command) error {
			if got := c.Count(vFlag.Name); got != 2 {
				t.Errorf("verbose count = %d, want 2", got)
			}

			if !c.Bool(vFlag.Name) {
				t.Error("verbose flag was not set")
			}

			return nil
		},
	}

	if err := cmd.Run(context.Background(), []string{t.Name(), "-vv"}); err != nil {
		t.Error(err)
	}
}
func TestVerboseFlagPersistent(t *testing.T) {
	flag := newTestVerboseFlag()
	cmd := cli.Command{
		Name:                   t.Name(),
		UseShortOptionHandling: true,
		Flags:                  []cli.Flag{flag},
		Commands: []*cli.Command{
			{
				Name: "sub",
				Action: func(_ context.Context, c *cli.Command) error {
					if got := c.Count(vFlag.Name); got != 2 {
						t.Errorf("verbose count = %d, want 2", got)
					}

					return nil
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), []string{t.Name(), "sub", "-vv"}); err != nil {
		t.Error(err)
	}
}

func newTestVerboseFlag() *cli.BoolFlag {
	return &cli.BoolFlag{
		Name:        vFlag.Name,
		Aliases:     append([]string(nil), vFlag.Aliases...),
		Usage:       vFlag.Usage,
		DefaultText: vFlag.DefaultText,
	}
}
