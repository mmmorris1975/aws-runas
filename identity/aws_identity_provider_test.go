package identity

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/mmmorris1975/aws-runas/shared"
	"sync"
	"testing"
)

func TestNewAwsIdentityProvider(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		p := NewAwsIdentityProvider(aws.Config{})
		if p == nil {
			t.Error("nil provider returned")
		}
	})

	t.Run("with logger", func(t *testing.T) {
		p := NewAwsIdentityProvider(aws.Config{}).WithLogger(nil)
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
	//stsApi
	sendError bool
}

func (c *mockStsClient) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if c.sendError {
		return nil, errors.New("error: GetCallerIdentity()")
	}

	return &sts.GetCallerIdentityOutput{
		Account: aws.String("123456789012"),
		Arn:     aws.String("arn:aws:iam::123456789012:user/bob"),
		UserId:  aws.String("AIDAB0B")}, nil
}

// An IAM client we can use for testing to avoid calls out to AWS
// In addition to the IAM API, we also create a number of private methods in order to manage that data used
// by the various IAM API calls.
type mockIamClient struct {
	iamApi
	sendError bool
}

func (c *mockIamClient) groups() []types.Group {
	return []types.Group{
		{GroupName: aws.String("group1")},
		{GroupName: aws.String("group2")},
		{GroupName: aws.String("group3")},
	}
}

func (c *mockIamClient) policies() []*mockIamPolicy {
	return []*mockIamPolicy{p1, p2, p3, p4, p5, p6, p7, p8, p9}
}

func (c *mockIamClient) policyNames() []string {
	a := make([]string, len(c.policies()))

	for i, p := range c.policies() {
		a[i] = *p.Policy.PolicyName
	}

	return a
}

func (c *mockIamClient) attachedPolicies() []types.AttachedPolicy {
	a := make([]types.AttachedPolicy, len(c.policies()))

	for i, p := range c.policies() {
		a[i] = types.AttachedPolicy{
			PolicyArn:  p.Arn,
			PolicyName: p.Policy.PolicyName,
		}
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

func (c *mockIamClient) ListGroupsForUser(context.Context, *iam.ListGroupsForUserInput, ...func(*iam.Options)) (*iam.ListGroupsForUserOutput, error) {
	if c.sendError {
		return nil, errors.New("error: ListGroupsForUserPages()")
	}

	out := &iam.ListGroupsForUserOutput{Groups: c.groups()}
	return out, nil
}

func (c *mockIamClient) ListUserPolicies(context.Context, *iam.ListUserPoliciesInput, ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	if c.sendError {
		return nil, errors.New("error: ListUserPoliciesPages()")
	}

	out := &iam.ListUserPoliciesOutput{PolicyNames: c.policyNames()}
	return out, nil
}

func (c *mockIamClient) GetUserPolicy(_ context.Context, in *iam.GetUserPolicyInput, _ ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	if c.sendError {
		return nil, errors.New("error: GetUserPolicy()")
	}

	p := c.lookupPolicy(in.PolicyName)
	if p == nil {
		return nil, new(types.NoSuchEntityException)
	}

	out := &iam.GetUserPolicyOutput{
		PolicyDocument: p.PolicyDocument,
		PolicyName:     p.Policy.PolicyName,
	}
	return out, nil
}

func (c *mockIamClient) ListAttachedUserPolicies(context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	if c.sendError {
		return nil, errors.New("error: ListAttachedUserPoliciesPages()")
	}

	out := &iam.ListAttachedUserPoliciesOutput{AttachedPolicies: c.attachedPolicies()}
	return out, nil
}

func (c *mockIamClient) ListGroupPolicies(context.Context, *iam.ListGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error) {
	if c.sendError {
		return nil, errors.New("error: ListGroupPoliciesPages()")
	}

	out := &iam.ListGroupPoliciesOutput{PolicyNames: c.policyNames()}
	return out, nil
}

func (c *mockIamClient) GetGroupPolicy(_ context.Context, in *iam.GetGroupPolicyInput, _ ...func(*iam.Options)) (*iam.GetGroupPolicyOutput, error) {
	if c.sendError {
		return nil, errors.New("error: GetGroupPolicy()")
	}

	p := c.lookupPolicy(in.GroupName)
	if p == nil {
		return nil, new(types.NoSuchEntityException)
	}

	out := &iam.GetGroupPolicyOutput{
		PolicyName:     p.Policy.PolicyName,
		PolicyDocument: p.PolicyDocument,
	}
	return out, nil
}

func (c *mockIamClient) ListAttachedGroupPolicies(context.Context, *iam.ListAttachedGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error) {
	if c.sendError {
		return nil, errors.New("error: ListAttachedGroupPoliciesPages()")
	}

	out := &iam.ListAttachedGroupPoliciesOutput{AttachedPolicies: c.attachedPolicies()}
	return out, nil
}

func (c *mockIamClient) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	if c.sendError {
		return nil, errors.New("error: GetPolicy()")
	}

	p := c.lookupPolicy(in.PolicyArn)
	if p == nil {
		return nil, new(types.NoSuchEntityException)
	}

	out := &iam.GetPolicyOutput{Policy: &p.Policy}
	return out, nil
}

func (c *mockIamClient) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	if c.sendError {
		return nil, errors.New("error: GetPolicyVersion()")
	}

	p := c.lookupPolicy(in.PolicyArn)
	if p == nil {
		return nil, new(types.NoSuchEntityException)
	}

	out := &iam.GetPolicyVersionOutput{
		PolicyVersion: &types.PolicyVersion{
			Document:         p.PolicyDocument,
			IsDefaultVersion: true,
			VersionId:        p.DefaultVersionId,
		},
	}
	return out, nil
}

// A type combining the capabilities of the iam.Policy and iam.PolicyDetail types so that we can manage
// the identity and policy document information in a single place.
type mockIamPolicy struct {
	types.Policy
	types.PolicyDetail
}

func NewMockIamPolicy(name string) *mockIamPolicy {
	arn := `arn:aws:iam::9876543210:policy/` + name

	return &mockIamPolicy{
		Policy: types.Policy{
			Arn:              &arn,
			DefaultVersionId: aws.String("default"),
			PolicyName:       &name,
		},
		PolicyDetail: types.PolicyDetail{PolicyName: &name},
	}
}

func (m *mockIamPolicy) WithPolicyDocument(doc string) *mockIamPolicy {
	m.PolicyDocument = &doc
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
