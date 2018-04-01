package config

import (
	"fmt"
	"github.com/mbndr/logo"
	"testing"
)

func TestCmdlineConfigHandlerAllNil(t *testing.T) {
	defer func() {
		if x := recover(); x != nil {
			t.Errorf("NewCmdlineConfigHandler() panic'd with all nil options")
		}
	}()
	NewCmdlineConfigHandler(nil, nil)
}

func TestNewCmdlineConfigHandler(t *testing.T) {
	defer func() {
		if x := recover(); x != nil {
			t.Errorf("Unexpected panic in NewCmdlineConfigHandler()")
		}
	}()
	NewCmdlineConfigHandler(&ConfigHandlerOpts{LogLevel: logo.FATAL}, new(CmdlineOptions))
}

func TestCmdlineConfigHandler_ConfigNil(t *testing.T) {
	defer func() {
		if x := recover(); x != nil {
			t.Errorf("Unexpected panic with all nil config")
		}
	}()
	h := NewCmdlineConfigHandler(nil, nil)
	h.Config(nil)
}

func ExampleCmdlineConfigHandler_Config() {
	opts := CmdlineOptions{
		Profile:       "mock",
		RoleArn:       "MockRole",
		MfaSerial:     "MFA",
		TokenDuration: "1s",
		CredDuration:  "1d",
	}
	c := new(AwsConfig)
	h := NewCmdlineConfigHandler(nil, &opts)
	h.Config(c)

	fmt.Println(c.Name)
	fmt.Println(c.RoleArn)
	fmt.Println(c.MfaSerial)
	fmt.Println(c.SessionDuration)
	fmt.Println(c.CredDuration)
	// Output:
	// mock
	// MockRole
	// MFA
	// 1s
	// 1d
}

func ExampleCmdlineConfigHandler_ConfigPartialOpts() {
	opts := CmdlineOptions{
		Profile:       "mock",
		TokenDuration: "1s",
		CredDuration:  "1d",
	}
	c := new(AwsConfig)
	h := NewCmdlineConfigHandler(nil, &opts)
	h.Config(c)

	fmt.Println(c.Name)
	fmt.Println(c.SessionDuration)
	fmt.Println(c.CredDuration)
	fmt.Println(c.RoleArn)
	fmt.Println(c.MfaSerial)
	// Output:
	// mock
	// 1s
	// 1d
	//
	//
}
