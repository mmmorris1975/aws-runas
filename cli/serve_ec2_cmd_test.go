package cli

import (
	"github.com/mmmorris1975/aws-runas/config"
	"os"
	"testing"
	"time"
)

func TestServeEC2Cmd_Action(t *testing.T) {
	errCh := make(chan error)

	t.Run("port flag", func(t *testing.T) {
		go func() {
			_ = os.Unsetenv("AWS_PROFILE")
			cmdlineCreds = new(config.AwsCredentials)
			errCh <- App.Run([]string{"mycmd", "-v", "serve", "ec2", "--port", "0"})
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
			os.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://127.0.0.1:4321/")
			defer os.Unsetenv("AWS_EC2_METADATA_SERVICE_ENDPOINT")

			cmdlineCreds = new(config.AwsCredentials)
			errCh <- App.Run([]string{"mycmd", "-v", "-v", "serve", "ec2"})
		}()

		select {
		case <-time.After(3 * time.Second):
		case err := <-errCh:
			t.Error(err)
		}
	})
}
