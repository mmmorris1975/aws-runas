package config

import "testing"

func TestAwsConfigDefault(t *testing.T) {
	c := new(AwsConfig)
	if c.defaultProfile != nil || c.sourceProfile != nil {
		t.Errorf("Expected defaultProfile and sourceProfile fields to be nil with default AwsConfig")
	}
}

func TestAwsConfigOnlyDefaultProfile(t *testing.T) {
	c := new(AwsConfig)
	c.defaultProfile = &AwsConfig{Region: "eu-mock-1", SessionDuration: "1m", CredDuration: "5m", MfaSerial: "0"}

	if c.GetRegion() != "eu-mock-1" || c.GetSessionDuration() != "1m" ||
		c.GetCredDuration() != "5m" || c.GetMfaSerial() != "0" {
		t.Errorf("Unexpected data for Region and SessionDuration")
	}
}

func TestAwsConfig(t *testing.T) {
	d := &AwsConfig{Region: "us-east-1", Name: "default"}
	s := &AwsConfig{Region: "us-east-2", Name: "ohio", SessionDuration: "12h", MfaSerial: "24687531"}
	c := &AwsConfig{CredDuration: "4h", Name: "config", RoleArn: "myRole", defaultProfile: d, sourceProfile: s}

	t.Run("GetCredDuration", func(t *testing.T) {
		if c.GetCredDuration() != "4h" {
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
		if c.GetSessionDuration() != "12h" {
			t.Errorf("Unexpected value for SessionDuration, Wanted: %s, Got: %s", "12h", c.GetSessionDuration())
		}
	})
}
