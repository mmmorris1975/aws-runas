package config

import (
	"fmt"
	"testing"
	"time"
)

func TestAwsConfigDefault(t *testing.T) {
	c := new(AwsConfig)
	if c.defaultProfile != nil || c.sourceProfile != nil {
		t.Errorf("Expected defaultProfile and sourceProfile fields to be nil with default AwsConfig")
	}
}

func ExampleAwsConfigOnlyDefaultProfile() {
	c := new(AwsConfig)
	c.defaultProfile = &AwsConfig{Region: "eu-mock-1", SessionDuration: 1 * time.Minute, CredDuration: 5 * time.Minute, MfaSerial: "0"}

	fmt.Println(c.GetRegion())
	fmt.Println(c.GetSessionDuration())
	fmt.Println(c.GetCredDuration())
	fmt.Println(c.GetMfaSerial())
	// Output:
	// eu-mock-1
	// 1m0s
	// 5m0s
	// 0
}

func ExampleAwsConfigOnlySourceProfile() {
	c := new(AwsConfig)
	c.sourceProfile = &AwsConfig{Region: "ap-mock-1", SessionDuration: 1 * time.Hour, CredDuration: 5 * time.Hour, MfaSerial: "000"}

	fmt.Println(c.GetRegion())
	fmt.Println(c.GetSessionDuration())
	fmt.Println(c.GetCredDuration())
	fmt.Println(c.GetMfaSerial())
	// Output:
	// ap-mock-1
	// 1h0m0s
	// 5h0m0s
	// 000
}

func TestAwsConfig(t *testing.T) {
	d := &AwsConfig{Region: "us-east-1", Name: "default"}
	s := &AwsConfig{Region: "us-east-2", Name: "ohio", SessionDuration: 12 * time.Hour, MfaSerial: "24687531"}
	c := &AwsConfig{CredDuration: 4 * time.Hour, Name: "config", RoleArn: "myRole", defaultProfile: d, sourceProfile: s}

	t.Run("GetCredDuration", func(t *testing.T) {
		if c.GetCredDuration() != 4*time.Hour {
			t.Errorf("Unexpected value for CredDuration, Wanted: %s, Got: %s", "4h", c.GetCredDuration())
		}
	})
	t.Run("GetMfaSerial", func(t *testing.T) {
		if c.GetMfaSerial() != "24687531" {
			t.Errorf("Unexpected value for MfaSerial, Wanted: %s, Got: %s", "24687531", c.GetMfaSerial())
		}
	})
	t.Run("GetRegion", func(t *testing.T) {
		if c.GetRegion() != "us-east-2" {
			t.Errorf("Unexpected value for Region, Wanted: %s, Got: %s", "us-east-2", c.GetRegion())
		}
	})
	t.Run("GetSessionDuration", func(t *testing.T) {
		if c.GetSessionDuration() != 12*time.Hour {
			t.Errorf("Unexpected value for SessionDuration, Wanted: %s, Got: %s", "12h", c.GetSessionDuration())
		}
	})
}
