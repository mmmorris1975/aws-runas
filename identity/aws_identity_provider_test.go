package identity

import (
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/awstesting/mock"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/mmmorris1975/aws-runas/shared"
	"sync"
	"testing"
)

func TestNewAwsIdentityProvider(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		p := NewAwsIdentityProvider(mock.Session)
		if p == nil {
			t.Error("nil provider returned")
		}
	})

	t.Run("nil config", func(t *testing.T) {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Did not receive expected panic calling NewSessionTokenCredentials with nil config")
			}
		}()
		NewAwsIdentityProvider(nil)
	})

	t.Run("with logger", func(t *testing.T) {
		p := NewAwsIdentityProvider(mock.Session).WithLogger(nil)
		if p.logger == nil {
			t.Errorf("data mismatch")
		}
	})
}

func TestAwsIdentityProvider_Identity(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		p := &awsIdentityProvider{stsClient: new(mockStsClient), logger: new(shared.DefaultLogger)}

		id, err := p.Identity()
		if err != nil {
			t.Error(err)
			return
		}

		if id.Username != "bob" || id.IdentityType != "user" || id.Provider != "AwsIdentityProvider" {
			t.Error("data mismatch")
		}
	})

	t.Run("error", func(t *testing.T) {
		p := &awsIdentityProvider{stsClient: &mockStsClient{sendError: true}, logger: new(shared.DefaultLogger)}
		if _, err := p.Identity(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func TestAwsIdentityProvider_Roles(t *testing.T) {
	p := &awsIdentityProvider{
		stsClient: new(mockStsClient),
		iamClient: new(mockIamClient),
		wg:        new(sync.WaitGroup),
		logger:    new(shared.DefaultLogger),
	}

	t.Run("no user", func(t *testing.T) {
		r, err := p.Roles()
		if err != nil {
			t.Error(err)
			return
		}

		if len(*r) != 9 {
			t.Error("did not get the expected number of roles returned")
		}
	})

	t.Run("with user", func(t *testing.T) {
		r, err := p.Roles("fred")
		if err != nil {
			t.Error(err)
			return
		}

		if len(*r) != 9 {
			t.Error("did not get the expected number of roles returned")
		}
	})

	t.Run("error", func(t *testing.T) {
		p := &awsIdentityProvider{stsClient: &mockStsClient{sendError: true}, logger: new(shared.DefaultLogger)}
		if _, err := p.Roles(); err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func Example_awsIdentityProvider_Roles() {
	p := &awsIdentityProvider{
		stsClient: new(mockStsClient),
		iamClient: new(mockIamClient),
		wg:        new(sync.WaitGroup),
		logger:    new(shared.DefaultLogger),
	}

	r, _ := p.Roles()
	if r != nil {
		for _, i := range *r {
			fmt.Println(i)
		}
	}
	// Output:
	// arn:aws:iam::111111111:role/p1
	// arn:aws:iam::222222222:role/p2a
	// arn:aws:iam::222222222:role/p2b
	// arn:aws:iam::333333333:role/p3y
	// arn:aws:iam::333333333:role/p3z
	// arn:aws:iam::444444444:role/p4
	// arn:aws:iam::666666666:role/p6
	// arn:aws:iam::666666666:role/p6a
	// arn:aws:iam::666666666:role/p6b
}

// An STS client we can use for testing to avoid calls out to AWS.
type mockStsClient struct {
	stsiface.STSAPI
	sendError bool
}

func (c *mockStsClient) GetCallerIdentity(*sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	if c.sendError {
		return nil, errors.New("error: GetCallerIdentity()")
	}

	return new(sts.GetCallerIdentityOutput).
		SetAccount("123456789012").
		SetArn("arn:aws:iam::123456789012:user/bob").
		SetUserId("AIDAB0B"), nil
}

// An IAM client we can use for testing to avoid calls out to AWS
// In addition to the IAM API, we also create a number of private methods in order to manage that data used
// by the various IAM API calls.
type mockIamClient struct {
	iamiface.IAMAPI
	sendError bool
}

func (c *mockIamClient) groups() []*iam.Group {
	return []*iam.Group{
		new(iam.Group).SetGroupName("group1"),
		new(iam.Group).SetGroupName("group2"),
		new(iam.Group).SetGroupName("group3"),
	}
}

func (c *mockIamClient) policies() []*mockIamPolicy {
	return []*mockIamPolicy{p1, p2, p3, p4, p5, p6, p7, p8, p9}
}

func (c *mockIamClient) policyNames() []*string {
	a := make([]*string, 0)

	for _, p := range c.policies() {
		a = append(a, p.Policy.PolicyName)
	}

	return a
}

func (c *mockIamClient) attachedPolicies() []*iam.AttachedPolicy {
	a := make([]*iam.AttachedPolicy, 0)

	for _, p := range c.policies() {
		a = append(a, &iam.AttachedPolicy{
			PolicyArn:  p.Arn,
			PolicyName: p.Policy.PolicyName,
		})
	}

	return a
}

func (c *mockIamClient) lookupPolicy(f *string) *mockIamPolicy {
	for _, p := range c.policies() {
		if *p.Arn == *f || *p.Policy.PolicyName == *f {
			return p
		}
	}

	return nil
}

func (c *mockIamClient) ListGroupsForUserPages(_ *iam.ListGroupsForUserInput,
	fn func(*iam.ListGroupsForUserOutput, bool) bool) error {
	if c.sendError {
		return errors.New("error: ListGroupsForUserPages()")
	}

	out := new(iam.ListGroupsForUserOutput).SetGroups(c.groups())
	fn(out, true)
	return nil
}

func (c *mockIamClient) ListUserPoliciesPages(_ *iam.ListUserPoliciesInput,
	fn func(*iam.ListUserPoliciesOutput, bool) bool) error {
	if c.sendError {
		return errors.New("error: ListUserPoliciesPages()")
	}

	out := new(iam.ListUserPoliciesOutput).SetPolicyNames(c.policyNames())
	fn(out, true)
	return nil
}

func (c *mockIamClient) GetUserPolicy(in *iam.GetUserPolicyInput) (*iam.GetUserPolicyOutput, error) {
	if c.sendError {
		return nil, errors.New("error: GetUserPolicy()")
	}

	p := c.lookupPolicy(in.PolicyName)
	if p == nil {
		return nil, fmt.Errorf(iam.ErrCodeNoSuchEntityException)
	}

	out := new(iam.GetUserPolicyOutput).SetPolicyName(*p.Policy.PolicyName).SetPolicyDocument(*p.PolicyDocument)
	return out, nil
}

func (c *mockIamClient) ListAttachedUserPoliciesPages(_ *iam.ListAttachedUserPoliciesInput,
	fn func(*iam.ListAttachedUserPoliciesOutput, bool) bool) error {
	if c.sendError {
		return errors.New("error: ListAttachedUserPoliciesPages()")
	}

	out := new(iam.ListAttachedUserPoliciesOutput).SetAttachedPolicies(c.attachedPolicies())
	fn(out, true)
	return nil
}

func (c *mockIamClient) ListGroupPoliciesPages(_ *iam.ListGroupPoliciesInput,
	fn func(*iam.ListGroupPoliciesOutput, bool) bool) error {
	if c.sendError {
		return errors.New("error: ListGroupPoliciesPages()")
	}

	out := new(iam.ListGroupPoliciesOutput).SetPolicyNames(c.policyNames())
	fn(out, true)
	return nil
}

func (c *mockIamClient) GetGroupPolicy(in *iam.GetGroupPolicyInput) (*iam.GetGroupPolicyOutput, error) {
	if c.sendError {
		return nil, errors.New("error: GetGroupPolicy()")
	}

	p := c.lookupPolicy(in.GroupName)
	if p == nil {
		return nil, fmt.Errorf(iam.ErrCodeNoSuchEntityException)
	}

	out := new(iam.GetGroupPolicyOutput).SetPolicyName(*p.Policy.PolicyName).SetPolicyDocument(*p.PolicyDocument)
	return out, nil
}

func (c *mockIamClient) ListAttachedGroupPoliciesPages(_ *iam.ListAttachedGroupPoliciesInput,
	fn func(*iam.ListAttachedGroupPoliciesOutput, bool) bool) error {
	if c.sendError {
		return errors.New("error: ListAttachedGroupPoliciesPages()")
	}

	out := new(iam.ListAttachedGroupPoliciesOutput).SetAttachedPolicies(c.attachedPolicies())
	fn(out, true)
	return nil
}

func (c *mockIamClient) GetPolicy(in *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
	if c.sendError {
		return nil, errors.New("error: GetPolicy()")
	}

	p := c.lookupPolicy(in.PolicyArn)
	if p == nil {
		return nil, fmt.Errorf(iam.ErrCodeNoSuchEntityException)
	}

	out := new(iam.GetPolicyOutput).SetPolicy(p.Policy)
	return out, nil
}

func (c *mockIamClient) GetPolicyVersion(in *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
	if c.sendError {
		return nil, errors.New("error: GetPolicyVersion()")
	}

	p := c.lookupPolicy(in.PolicyArn)
	if p == nil {
		return nil, fmt.Errorf(iam.ErrCodeNoSuchEntityException)
	}

	ver := new(iam.PolicyVersion).SetVersionId(*p.DefaultVersionId).SetIsDefaultVersion(true).
		SetDocument(*p.PolicyDocument)
	out := new(iam.GetPolicyVersionOutput).SetPolicyVersion(ver)
	return out, nil
}

// A type combining the capabilities of the iam.Policy and iam.PolicyDetail types so that we can manage
// the identity and policy document information in a single place.
type mockIamPolicy struct {
	*iam.Policy
	*iam.PolicyDetail
}

func NewMockIamPolicy(name string) *mockIamPolicy {
	arn := `arn:aws:iam::9876543210:policy/` + name

	return &mockIamPolicy{
		Policy:       new(iam.Policy).SetPolicyName(name).SetArn(arn).SetDefaultVersionId("default"),
		PolicyDetail: new(iam.PolicyDetail).SetPolicyName(name),
	}
}

func (m *mockIamPolicy) WithPolicyDocument(doc string) *mockIamPolicy {
	m.SetPolicyDocument(doc)
	return m
}

var p1 = NewMockIamPolicy("stringAction-stringRole").WithPolicyDocument(`
{"Statement": [
  {
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": "arn:aws:iam::111111111:role/p1"
  }
]}
`)

var p2 = NewMockIamPolicy("stringAction-arrayRole").WithPolicyDocument(`
{"Statement": [
  {
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": ["arn:aws:iam::222222222:role/p2a", "arn:aws:iam::222222222:role/p2b"]
  }
]}
`)

var p3 = NewMockIamPolicy("arrayAction-arrayRole").WithPolicyDocument(`
{"Statement": [
  {
    "Effect": "Allow",
    "Action": ["sts:AssumeRole", "s3:*"],
    "Resource": ["arn:aws:iam::333333333:role/p3y", "arn:aws:s3:::my-bucket", "arn:aws:iam::333333333:role/p3z"]
  }
]}
`)

var p4 = NewMockIamPolicy("arrayAction-stringRole").WithPolicyDocument(`
{"Statement": [
  {
    "Effect": "Allow",
    "Action": ["sts:AssumeRole"],
    "Resource": "arn:aws:iam::444444444:role/p4"
  }
]}
`)

var p5 = NewMockIamPolicy("deny").WithPolicyDocument(`
{"Statement": [
  {"Effect": "None"},
  {"Effect": "Deny", "Action": "sts:AssumeRole"}
]}
`)

var p6 = NewMockIamPolicy("compound").WithPolicyDocument(`
{"Statement": [
  {
    "Effect": "Allow",
    "Action": ["sts:AssumeRole"],
    "Resource": "arn:aws:iam::666666666:role/p6"
  },
  {
    "Effect": "Deny",
    "Action": ["sts:AssumeRole"],
    "Resource": "arn:aws:iam::666666666:role/Administrator"
  },
  {
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": ["arn:aws:iam::666666666:role/p6a", "arn:aws:iam::666666666:role/p6b"]
  }
]}
`)

var p7 = NewMockIamPolicy("empty-statement").WithPolicyDocument(`
{"Statement": []}
`)

var p8 = NewMockIamPolicy("empty-doc").WithPolicyDocument(``)
var p9 = NewMockIamPolicy("bad-json").WithPolicyDocument(`{Statement: []}`)
