package config

import (
	"fmt"
	"os"
	"testing"
)

func TestNewEnvConfigHandlerNilOpts(t *testing.T) {
	defer func() {
		if x := recover(); x != nil {
			t.Errorf("Unexpected panic from NewEnvConfigHandler with nil opts")
		}
	}()
	NewEnvConfigHandler(nil)
}

func TestEnvConfigHandler_ConfigNil(t *testing.T) {
	defer func() {
		if x := recover(); x != nil {
			t.Errorf("Unexpected panic from NewEnvConfigHandler with nil config")
		}
	}()
	h := NewEnvConfigHandler(new(ConfigHandlerOpts))
	h.Config(nil)
}

func ExampleEnvConfigHandler_Config() {
	os.Setenv("AWS_PROFILE", "mock_profile")
	defer os.Unsetenv("AWS_PROFILE")
	os.Setenv("AWS_REGION", "mock_region")
	defer os.Unsetenv("AWS_REGION")
	os.Setenv("SESSION_TOKEN_DURATION", "24h")
	defer os.Unsetenv("SESSION_TOKEN_DURATION")
	os.Setenv("CREDENTIALS_DURATION", "6h")
	defer os.Unsetenv("CREDENTIALS_DURATION")

	c := new(AwsConfig)
	h := NewEnvConfigHandler(new(ConfigHandlerOpts))
	h.Config(c)

	fmt.Println(c.Name)
	fmt.Println(c.Region)
	fmt.Println(c.SessionDuration)
	fmt.Println(c.CredDuration)
	// Output:
	// mock_profile
	// mock_region
	// 24h0m0s
	// 6h0m0s
}

func ExampleEnvConfigHandler_ConfigPartial() {
	os.Setenv("AWS_PROFILE", "mock_profile")
	defer os.Unsetenv("AWS_PROFILE")
	os.Setenv("SESSION_TOKEN_DURATION", "15h")
	defer os.Unsetenv("SESSION_TOKEN_DURATION")

	c := new(AwsConfig)
	h := NewEnvConfigHandler(new(ConfigHandlerOpts))
	h.Config(c)

	fmt.Println(c.Name)
	fmt.Println(c.SessionDuration)
	fmt.Println(c.CredDuration)
	fmt.Println(c.Region)
	// Output:
	// mock_profile
	// 15h0m0s
	// 0s
	//

}
