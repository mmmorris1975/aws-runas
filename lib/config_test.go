package lib

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/mbndr/logo"
	"os"
	"testing"
)

func init() {
	os.Unsetenv("AWS_DEFAULT_PROFILE")
	os.Unsetenv("AWS_PROFILE")
	os.Unsetenv("AWS_REGION")
}

func TestNilProfileName(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", "config/test/aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")

	p, err := getProfile(nil)
	if err == nil {
		t.Errorf("Expected error with nil profile name, but received: %+v", p)
	} else {
		t.Logf("Expected nil profile name error: %v", err)
	}
}

func TestEmptyProfileName(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", "config/test/aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")

	p, err := getProfile(aws.String(""))
	if err == nil {
		t.Errorf("Expected error for empty profile name, but received: %+v", p)
	} else {
		t.Logf("Expected empty profile name error: %v", err)
	}
}

func TestBadProfileName(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", "config/test/aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")

	name := "lkajiq"
	p, err := getProfile(aws.String(name))
	if err == nil {
		t.Errorf("Expected error for bad profile name, but received: %+v", p)
	} else {
		t.Logf("Expected bad profile name error: %v", err)
	}
}

func TestUnparsableRoleArn(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", "config/test/aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")

	p, err := getProfile(aws.String("has_bad_role"))
	if err == nil {
		t.Errorf("Expected error for unparsable role arn, but received: %+v", p)
	} else {
		t.Logf("Expected unparsable arn error: %v", err)
	}
}

func TestNonIamRoleArn(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", "config/test/aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")

	p, err := getProfile(aws.String("has_s3_arn"))
	if err == nil {
		t.Errorf("Expected error for non-iam role arn, but received: %+v", p)
	} else {
		t.Logf("Expected non-iam arn error: %v", err)
	}
}

func TestBadSourceProfile(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", "config/test/aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")
	name := "has_role_bad_source"

	p, err := getProfile(aws.String(name))
	if err == nil {
		t.Errorf("Expected error for invalid source_profile, but received: %+v", p)
	} else {
		t.Logf("Expected invalid source_profile error: %v", err)
	}
}

func TestNoSourceProfile(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", "config/test/aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")
	name := "has_role_no_source"

	p, err := getProfile(aws.String(name))
	if err == nil {
		t.Errorf("Expected error for missing source_profile, but received: %+v", p)
	} else {
		t.Logf("Expected missing source_profile error: %v", err)
	}
}

func ExampleGetProfileNoRoleMfa() {
	os.Setenv("AWS_CONFIG_FILE", "config/test/aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")
	name := "basic"

	p, err := getProfile(aws.String(name))
	if err != nil {
		fmt.Printf("Error getting profile %s: %v", name, err)
	}

	fmt.Println(p.Name)
	fmt.Println(p.Region)
	fmt.Println(p.SourceProfile)
	fmt.Println(p.MfaSerial)
	// Output:
	// basic
	// us-west-2
	//
	//
	//
}

func ExampleGetProfileRoleNoMfa() {
	os.Setenv("AWS_CONFIG_FILE", "config/test/aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")
	name := "has_role"

	p, err := getProfile(aws.String(name))
	if err != nil {
		fmt.Printf("Error getting profile %s: %v", name, err)
	}

	fmt.Println(p.Name)
	fmt.Println(p.SourceProfile)
	fmt.Println(p.RoleArn)
	fmt.Println(p.MfaSerial)
	// Output:
	// has_role
	// default
	// arn:aws:iam::012345678901:mfa/my_iam_user
	//
}

func ExampleGetProfileRoleMfa() {
	os.Setenv("AWS_CONFIG_FILE", "config/test/aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")
	name := "has_role_explicit_mfa"

	p, err := getProfile(aws.String(name))
	if err != nil {
		fmt.Printf("Error getting profile %s: %v", name, err)
	}

	fmt.Println(p.Name)
	fmt.Println(p.SourceProfile)
	fmt.Println(p.RoleArn)
	fmt.Println(p.MfaSerial)
	// Output:
	// has_role_explicit_mfa
	// default
	// arn:aws:iam::012345678901:mfa/my_iam_user
	// 87654321
}

func ExampleGetProfileRoleInheritMfa() {
	os.Setenv("AWS_CONFIG_FILE", "config/test/aws.cfg")
	defer os.Unsetenv("AWS_CONFIG_FILE")
	name := "has_role_inherit_mfa"

	p, err := getProfile(aws.String(name))
	if err != nil {
		fmt.Printf("Error getting profile %s: %v", name, err)
	}

	fmt.Println(p.Name)
	fmt.Println(p.SourceProfile)
	fmt.Println(p.RoleArn)
	fmt.Println(p.MfaSerial)
	// Output:
	// has_role_inherit_mfa
	// alt_default
	// arn:aws:iam::012345678901:mfa/my_iam_user
	// 12345678
}

func TestNewConfigManagerBadConf(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", "nope")
	defer os.Unsetenv("AWS_CONFIG_FILE")
	m, err := NewAwsConfigManager(new(ConfigManagerOptions))
	_, err = m.GetProfile(aws.String("basic"))
	if err == nil {
		t.Errorf("Expected error for invalid config file, but NewAwsConfigManager() succeeded")
	}
}

func getProfile(name *string) (*AWSProfile, error) {
	cm, err := NewAwsConfigManager(&ConfigManagerOptions{LogLevel: logo.INFO})
	if err != nil {
		return nil, err
	}

	p, err := cm.GetProfile(name)
	if err != nil {
		return nil, err
	}

	return p, nil
}
