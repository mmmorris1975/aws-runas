package credentials

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"testing"
)

func TestNewAwsIdentityManager(t *testing.T) {
	s := session.Must(session.NewSession())
	m := NewAwsIdentityManager(s).WithLogger(aws.NewDefaultLogger())
	if m == nil {
		t.Error("got nil manager")
	}
}

func TestNewAwsIdentityManager_GetCallerIdentity(t *testing.T) {
	m := &AwsIdentityManager{client: new(mockStsClient)}
	id, err := m.GetCallerIdentity()
	if err != nil {
		t.Errorf("error in GetCallerIdentity(): %v", err)
		return
	}

	if id.IdentityType != "user" {
		t.Error("bad identity type")
	}

	if id.UserName != "bob" {
		t.Error("bad user name")
	}

	if *id.Identity.UserId != "AIDAB0B" {
		t.Error("bad AWS user id")
	}
}
