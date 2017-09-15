package main

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go/service/iam"
	"log"
	"net/url"
)

type RoleGetter interface {
	GetInlineRoles(name string) *[]string
	GetAttachedRoles(name string) *[]string
}

func convertAttachedPolicies(p []*iam.AttachedPolicy) *[]string {
	policies := make([]string, len(p))
	for _, v := range p {
		policies = append(policies, *v.PolicyName)
	}
	return &policies
}

func parsePolicy(p *string) *[]string {
	roles := make([]string, 0)
	polJson := make(map[string]interface{})

	parsedDoc, err := url.QueryUnescape(*p)
	if err != nil {
		log.Printf("%v", err)
		return &roles
	}

	json.Unmarshal([]byte(parsedDoc), &polJson)
	switch t := polJson["Statement"].(type) {
	case []interface{}:
		for _, v := range t {
			log.Printf("%v\n", v)
			// TODO probably need to recurse?
		}
	case map[string]interface{}:
		if t["Effect"] == "Allow" && t["Action"] == "sts:AssumeRole" {
			log.Printf("%v\n", t["Resource"])
			// TODO possible this is a string or an array?
		}
	}

	return &roles
}

type UserRoleGetter struct {
	Client *iam.IAM
}

func (u *UserRoleGetter) GetInlineRoles(name string) *[]string {
	roles := make([]string, 0)
	listPolInput := iam.ListUserPoliciesInput{UserName: &name}
	getPolInput := iam.GetUserPolicyInput{UserName: &name}

	truncated := true
	for truncated {
		polList, err := u.Client.ListUserPolicies(&listPolInput)
		if err != nil {
			log.Printf("ERROR %v\n", err)
			break
		}

		for _, p := range polList.PolicyNames {
			getPolInput.PolicyName = p
			res, err := u.Client.GetUserPolicy(&getPolInput)
			if err != nil {
				log.Printf("ERROR %v\n", err)
				continue
			}
			roles = append(roles, *parsePolicy(res.PolicyDocument)...)
		}

		truncated = *polList.IsTruncated
		if truncated {
			listPolInput.Marker = polList.Marker
		}
	}

	return &roles
}

func (u *UserRoleGetter) GetAttachedRoles(name string) *[]string {
	roles := make([]string, 0)
	listPolInput := iam.ListAttachedUserPoliciesInput{UserName: &name}

	truncated := true
	for truncated {
		polList, err := u.Client.ListAttachedUserPolicies(&listPolInput)
		if err != nil {
			log.Printf("ERROR %v\n", err)
			break
		}

		for _, p := range polList.AttachedPolicies {
			getPolInput := iam.GetPolicyInput{PolicyArn: p.PolicyArn}
			getPolRes, err := u.Client.GetPolicy(&getPolInput)
			if err != nil {
				log.Printf("ERROR %v\n", err)
				continue
			}

			getPolVerInput := iam.GetPolicyVersionInput{PolicyArn: getPolRes.Policy.Arn, VersionId: getPolRes.Policy.DefaultVersionId}
			getPolVerRes, err := u.Client.GetPolicyVersion(&getPolVerInput)
			if err != nil {
				log.Printf("ERROR %v\n", err)
				continue
			}

			roles = append(roles, *parsePolicy(getPolVerRes.PolicyVersion.Document)...)
		}

		truncated = *polList.IsTruncated
		if truncated {
			listPolInput.Marker = polList.Marker
		}
	}

	return &roles
}

type GroupRoleGetter struct {
	Client *iam.IAM
}

func (g *GroupRoleGetter) GetInlineRoles(name string) *[]string {
	roles := make([]string, 0)
	listPolInput := iam.ListGroupPoliciesInput{GroupName: &name}
	getPolInput := iam.GetGroupPolicyInput{GroupName: &name}

	truncated := true
	for truncated {
		polList, err := g.Client.ListGroupPolicies(&listPolInput)
		if err != nil {
			log.Printf("ERROR %v\n", err)
			break
		}

		for _, p := range polList.PolicyNames {
			getPolInput.PolicyName = p
			res, err := g.Client.GetGroupPolicy(&getPolInput)
			if err != nil {
				log.Printf("ERROR %v\n", err)
				continue
			}
			roles = append(roles, *parsePolicy(res.PolicyDocument)...)
		}

		truncated = *polList.IsTruncated
		if truncated {
			listPolInput.Marker = polList.Marker
		}
	}

	return &roles
}

func (g *GroupRoleGetter) GetAttachedRoles(name string) *[]string {
	roles := make([]string, 0)
	listPolInput := iam.ListAttachedGroupPoliciesInput{GroupName: &name}

	truncated := true
	for truncated {
		polList, err := g.Client.ListAttachedGroupPolicies(&listPolInput)
		if err != nil {
			log.Printf("ERROR %v\n", err)
			break
		}

		for _, p := range polList.AttachedPolicies {
			getPolInput := iam.GetPolicyInput{PolicyArn: p.PolicyArn}
			getPolRes, err := g.Client.GetPolicy(&getPolInput)
			if err != nil {
				log.Printf("ERROR %v\n", err)
				continue
			}

			getPolVerInput := iam.GetPolicyVersionInput{PolicyArn: getPolRes.Policy.Arn, VersionId: getPolRes.Policy.DefaultVersionId}
			getPolVerRes, err := g.Client.GetPolicyVersion(&getPolVerInput)
			if err != nil {
				log.Printf("ERROR %v\n", err)
				continue
			}

			roles = append(roles, *parsePolicy(getPolVerRes.PolicyVersion.Document)...)
		}

		truncated = *polList.IsTruncated
		if truncated {
			listPolInput.Marker = polList.Marker
		}
	}

	return &roles
}
