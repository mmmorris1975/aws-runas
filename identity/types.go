package identity

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Identity is the type used to store information for IAM or SAML user identity.
type Identity struct {
	IdentityType string
	Provider     string
	Username     string
}

// Roles is the list of roles the identity is allowed to assume.
type Roles []string

// Provider is the interface which conforming identity providers will adhere to.
type Provider interface {
	// Identity will return the Identity information for a user.
	Identity() (*Identity, error)
	// Roles returns the list of Roles the provided user is allowed to use.
	Roles(user ...string) (*Roles, error)
}

type stsApi interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type iamApi interface {
	iam.ListGroupsForUserAPIClient
	iam.ListUserPoliciesAPIClient
	iam.ListAttachedUserPoliciesAPIClient
	iam.ListGroupPoliciesAPIClient
	iam.ListAttachedGroupPoliciesAPIClient
	GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	GetUserPolicy(ctx context.Context, params *iam.GetUserPolicyInput, optFns ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
	GetGroupPolicy(ctx context.Context, params *iam.GetGroupPolicyInput, optFns ...func(*iam.Options)) (*iam.GetGroupPolicyOutput, error)
}
