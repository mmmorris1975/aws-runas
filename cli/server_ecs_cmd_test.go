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
