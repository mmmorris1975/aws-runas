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

func findRoles(data interface{}) *[]string {
	roles := make([]string, 0)

	switch t := data.(type) {
	case []interface{}:
		for _, v := range t {
			roles = append(roles, *findRoles(v)...)
		}
	case map[string]interface{}:
		var actionAssumeRole bool

		if t["Effect"] == "Allow" {
			switch v := t["Action"].(type) {
			case string:
				if v == "sts:AssumeRole" {
					actionAssumeRole = true
				}
			case []string:
				for _, val := range v {
					if val == "sts:AssumeRole" {
						actionAssumeRole = true
					}
				}
			}

			if actionAssumeRole {
				switch x := t["Resource"].(type) {
				case string:
					roles = append(roles, x)
				case []interface{}:
					// The compiler tells me that if it's not a string, it's this (not []string)
					for _, j := range x {
						roles = append(roles, j.(string))
					}
				}
			}
		}
	}

	return &roles
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
	roles = *findRoles(polJson["Statement"])

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
