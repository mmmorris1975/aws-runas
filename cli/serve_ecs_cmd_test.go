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
	"github.com/mmmorris1975/aws-runas/config"
	"os"
	"testing"
	"time"
)

func TestServeECSCmd_Action(t *testing.T) {
	errCh := make(chan error)

	t.Run("random port", func(t *testing.T) {
		go func() {
			_ = os.Unsetenv("AWS_PROFILE")
			cmdlineCreds = new(config.AwsCredentials)
			errCh <- App.Run([]string{"mycmd", "-v", "serve", "ecs"})
		}()

		select {
		case <-time.After(3 * time.Second):
		case err := <-errCh:
			t.Error(err)
		}
	})

	t.Run("env var", func(t *testing.T) {
		go func() {
			_ = os.Unsetenv("AWS_PROFILE")
			os.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://127.0.0.1:43210/ecs")
			defer os.Unsetenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")

			cmdlineCreds = new(config.AwsCredentials)
			errCh <- App.Run([]string{"mycmd", "-v", "-v", "serve", "ecs"})
		}()

		select {
		case <-time.After(3 * time.Second):
		case err := <-errCh:
			t.Error(err)
		}
	})
}
