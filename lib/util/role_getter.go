package util

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/iam"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Roles is a container for IAM role ARN
type Roles []string

// Dedup returns a sorted set of roles with duplicates removed
func (r Roles) Dedup() Roles {
	m := make(map[string]bool)

	for _, v := range r {
		trimV := strings.TrimSpace(v)
		if len(trimV) > 0 {
			m[trimV] = true
		}
	}

	a := make([]string, 0)
	for k := range m {
		a = append(a, k)
	}

	sort.Strings(a)
	return Roles(a)
}

// RoleGetter is the interface for providing a mechanism to retrieve a set of Roles
type RoleGetter interface {
	Roles() Roles
}

// NewAwsRoleGetter creates a RoleGetter to retrieve AWS IAM roles for the specified user
func NewAwsRoleGetter(c client.ConfigProvider, user string) RoleGetter {
	return &awsRoleGetter{client: c, user: user, wg: new(sync.WaitGroup)}
}

type awsRoleGetter struct {
	client client.ConfigProvider
	wg     *sync.WaitGroup
	user   string
}

// Get the explicitly configured IAM roles from the user's IAM account
// and groups, filtering out any roles which contain any wildcard characters.
// Roles from inline and attached IAM polices are discovered.  Access to roles
// which are implicitly granted (via policies like the AWS-managed administrator
// or IAM full access) are not discovered by this method.
func (r *awsRoleGetter) Roles() Roles {
	res := make([]string, 0)
	ch := make(chan string, 8)

	go r.roles(ch)

	for i := range ch {
		if !strings.Contains(i, "*") {
			res = append(res, i)
			//r.log.Debugf("Found role ARN: %s", i)
		}
	}

	return Roles(res).Dedup()
}

func (r *awsRoleGetter) roles(ch chan<- string) {
	defer close(ch)
	c := iam.New(r.client)

	r.wg.Add(2)
	go r.inlineUserRoles(c, ch)
	go r.attachedUserRoles(c, ch)

	i := iam.ListGroupsForUserInput{UserName: aws.String(r.user)}
	truncated := true
	for truncated {
		g, err := c.ListGroupsForUser(&i)
		if err != nil {
			//r.log.Errorf("Error getting IAM Group list for %s: %v", r.user, err)
		}

		for _, grp := range g.Groups {
			//r.log.Debugf("GROUP: %s", *grp.GroupName)
			r.wg.Add(2)
			go r.inlineGroupRoles(c, grp.GroupName, ch)
			go r.attachedGroupRoles(c, grp.GroupName, ch)
		}

		truncated = *g.IsTruncated
		if truncated {
			i.Marker = g.Marker
		}
	}

	r.wg.Wait()
}

func (r *awsRoleGetter) inlineUserRoles(c *iam.IAM, ch chan<- string) {
	defer r.wg.Done()
	listPolInput := iam.ListUserPoliciesInput{UserName: aws.String(r.user)}
	getPolInput := iam.GetUserPolicyInput{UserName: aws.String(r.user)}

	truncated := true
	for truncated {
		polList, err := c.ListUserPolicies(&listPolInput)
		if err != nil {
			//r.log.Errorf("Error calling ListUserPolicies(): %v", err)
			break
		}

		for _, p := range polList.PolicyNames {
			getPolInput.PolicyName = p
			res, err := c.GetUserPolicy(&getPolInput)
			if err != nil {
				//r.log.Errorf("Error calling GetUserPolicy(): %v", err)
				continue
			}

			roles, err := parsePolicy(res.PolicyDocument)
			if err != nil {
				//r.log.Errorf("Error parsing policy document: %v", err)
				continue
			}

			for _, v := range roles {
				ch <- v
			}
		}

		truncated = *polList.IsTruncated
		if truncated {
			listPolInput.Marker = polList.Marker
		}
	}
}

func (r *awsRoleGetter) attachedUserRoles(c *iam.IAM, ch chan<- string) {
	defer r.wg.Done()
	listPolInput := iam.ListAttachedUserPoliciesInput{UserName: aws.String(r.user)}

	truncated := true
	for truncated {
		polList, err := c.ListAttachedUserPolicies(&listPolInput)
		if err != nil {
			//r.log.Errorf("Error calling ListAttachedUserPolicies(): %v", err)
			break
		}

		for _, p := range polList.AttachedPolicies {
			getPolInput := iam.GetPolicyInput{PolicyArn: p.PolicyArn}
			getPolRes, err := c.GetPolicy(&getPolInput)
			if err != nil {
				//r.log.Errorf("Error calling GetPolicy(): %v", err)
				continue
			}

			getVerInput := iam.GetPolicyVersionInput{PolicyArn: getPolRes.Policy.Arn, VersionId: getPolRes.Policy.DefaultVersionId}
			getVerRes, err := c.GetPolicyVersion(&getVerInput)
			if err != nil {
				//r.log.Errorf("Error calling GetPolicyVersion(): %v", err)
				continue
			}

			roles, err := parsePolicy(getVerRes.PolicyVersion.Document)
			if err != nil {
				//r.log.Errorf("Error parsing policy document: %v", err)
				continue
			}

			for _, v := range roles {
				ch <- v
			}
		}

		truncated = *polList.IsTruncated
		if truncated {
			listPolInput.Marker = polList.Marker
		}
	}
}

func (r *awsRoleGetter) inlineGroupRoles(c *iam.IAM, g *string, ch chan<- string) {
	defer r.wg.Done()
	listPolInput := iam.ListGroupPoliciesInput{GroupName: g}
	getPolInput := iam.GetGroupPolicyInput{GroupName: g}

	truncated := true
	for truncated {
		polList, err := c.ListGroupPolicies(&listPolInput)
		if err != nil {
			//r.log.Errorf("Error calling ListGroupPolicies(): %v", err)
			break
		}

		for _, p := range polList.PolicyNames {
			getPolInput.PolicyName = p
			res, err := c.GetGroupPolicy(&getPolInput)
			if err != nil {
				//r.log.Errorf("Error calling GetGroupPolicy(): %v", err)
				continue
			}

			roles, err := parsePolicy(res.PolicyDocument)
			if err != nil {
				//r.log.Errorf("Error parsing policy document: %v", err)
				continue
			}

			for _, v := range roles {
				ch <- v
			}
		}

		truncated = *polList.IsTruncated
		if truncated {
			listPolInput.Marker = polList.Marker
		}
	}
}

func (r *awsRoleGetter) attachedGroupRoles(c *iam.IAM, g *string, ch chan<- string) {
	defer r.wg.Done()
	listPolInput := iam.ListAttachedGroupPoliciesInput{GroupName: g}

	truncated := true
	for truncated {
		polList, err := c.ListAttachedGroupPolicies(&listPolInput)
		if err != nil {
			//r.log.Errorf("Error calling ListAttachedGroupPolicies(): %v", err)
			break
		}

		for _, p := range polList.AttachedPolicies {
			getPolInput := iam.GetPolicyInput{PolicyArn: p.PolicyArn}
			getPolRes, err := c.GetPolicy(&getPolInput)
			if err != nil {
				//r.log.Errorf("Error calling GetPolicy(): %v", err)
				continue
			}

			getVerInput := iam.GetPolicyVersionInput{PolicyArn: getPolRes.Policy.Arn, VersionId: getPolRes.Policy.DefaultVersionId}
			getVerRes, err := c.GetPolicyVersion(&getVerInput)
			if err != nil {
				//r.log.Errorf("Error calling GetPolicyVersion(): %v", err)
				continue
			}

			roles, err := parsePolicy(getVerRes.PolicyVersion.Document)
			if err != nil {
				//r.log.Errorf("Error parsing policy document: %v", err)
				continue
			}

			for _, v := range roles {
				ch <- v
			}
		}

		truncated = *polList.IsTruncated
		if truncated {
			listPolInput.Marker = polList.Marker
		}
	}
}

func parsePolicy(doc *string) (Roles, error) {
	polJson := make(map[string]interface{})

	parsedDoc, err := url.QueryUnescape(*doc)
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(parsedDoc), &polJson)
	roles := findRoles(polJson["Statement"])

	return Roles(*roles), nil
}

func findRoles(data interface{}) *[]string {
	roles := make([]string, 0)

	switch t := data.(type) {
	case []interface{}:
		for _, v := range t {
			roles = append(roles, *findRoles(v)...)
		}
	case map[string]interface{}:
		var isAssumeRole bool
		assumeRoleAction := "sts:AssumeRole"

		if t["Effect"] == "Allow" {
			switch v := t["Action"].(type) {
			case string:
				if v == assumeRoleAction {
					isAssumeRole = true
				}
			case []string:
				for _, val := range v {
					if val == assumeRoleAction {
						isAssumeRole = true
					}
				}
			}

			if isAssumeRole {
				switch r := t["Resource"].(type) {
				case string:
					roles = append(roles, r)
				case []interface{}:
					// One would have hoped this was a []string, but the compiler says otherwise
					for _, v := range r {
						roles = append(roles, v.(string))
					}
				}
			}
		}
	}

	return &roles
}
