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

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mmmorris1975/aws-runas/cli"
)

// Version is managed at compile-time.
var Version = "0.0.0"

func main() {
	cli.App.Version = Version

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.App.RunContext(ctx, os.Args); err != nil {
		stop()
		log.Fatal(err)
	}
}
