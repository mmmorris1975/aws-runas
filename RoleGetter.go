package main

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/mbndr/logo"
	"net/url"
)

type RoleGetter interface {
	GetInlineRoles(name string) *[]string
	GetAttachedRoles(name string) *[]string
	GetInlineRolesChan(name string, c chan *[]string)
	GetAttachedRolesChan(name string, c chan *[]string)
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

func parsePolicy(p *string) (*[]string, error) {
	roles := make([]string, 0)
	polJson := make(map[string]interface{})

	parsedDoc, err := url.QueryUnescape(*p)
	if err != nil {
		return &roles, err
	}

	json.Unmarshal([]byte(parsedDoc), &polJson)
	roles = *findRoles(polJson["Statement"])

	return &roles, nil
}

type UserRoleGetter struct {
	Client *iam.IAM
	Logger *logo.Logger
}

func (u *UserRoleGetter) GetInlineRoles(name string) *[]string {
	u.Logger.Debugf("In GetInlineRoles() with param: %s", name)
	roles := make([]string, 0)
	listPolInput := iam.ListUserPoliciesInput{UserName: &name}
	getPolInput := iam.GetUserPolicyInput{UserName: &name}

	truncated := true
	for truncated {
		polList, err := u.Client.ListUserPolicies(&listPolInput)
		if err != nil {
			u.Logger.Errorf("Error calling ListUserPolicies(): %v", err)
			break
		}

		for _, p := range polList.PolicyNames {
			getPolInput.PolicyName = p
			res, err := u.Client.GetUserPolicy(&getPolInput)
			if err != nil {
				u.Logger.Errorf("Error calling GetUserPolicy(): %v", err)
				continue
			}

			r, err := parsePolicy(res.PolicyDocument)
			if err != nil {
				u.Logger.Errorf("Error parsing policy document: %v", err)
				continue
			}

			roles = append(roles, *r...)
		}

		truncated = *polList.IsTruncated
		if truncated {
			listPolInput.Marker = polList.Marker
		}
	}

	u.Logger.Debugf("USER INLINE ROLES: %+v", roles)
	return &roles
}

func (u *UserRoleGetter) GetAttachedRoles(name string) *[]string {
	u.Logger.Debugf("In GetAttachedRoles() with param: %s", name)
	roles := make([]string, 0)
	listPolInput := iam.ListAttachedUserPoliciesInput{UserName: &name}

	truncated := true
	for truncated {
		polList, err := u.Client.ListAttachedUserPolicies(&listPolInput)
		if err != nil {
			u.Logger.Errorf("Error calling ListAttachedUserPolicies(): %v", err)
			break
		}

		for _, p := range polList.AttachedPolicies {
			getPolInput := iam.GetPolicyInput{PolicyArn: p.PolicyArn}
			getPolRes, err := u.Client.GetPolicy(&getPolInput)
			if err != nil {
				u.Logger.Errorf("Error calling GetPolicy(): %v", err)
				continue
			}

			getPolVerInput := iam.GetPolicyVersionInput{PolicyArn: getPolRes.Policy.Arn, VersionId: getPolRes.Policy.DefaultVersionId}
			getPolVerRes, err := u.Client.GetPolicyVersion(&getPolVerInput)
			if err != nil {
				u.Logger.Errorf("Error calling GetPolicyVersion(): %v", err)
				continue
			}

			r, err := parsePolicy(getPolVerRes.PolicyVersion.Document)
			if err != nil {
				u.Logger.Errorf("Error parsing policy document: %v", err)
				continue
			}

			roles = append(roles, *r...)
		}

		truncated = *polList.IsTruncated
		if truncated {
			listPolInput.Marker = polList.Marker
		}
	}

	u.Logger.Debugf("USER ATTACHED ROLES: %+v", roles)
	return &roles
}

func (u *UserRoleGetter) GetInlineRolesChan(name string, c chan *[]string) {
	roles := u.GetInlineRoles(name)
	c <- roles
}

func (u *UserRoleGetter) GetAttachedRolesChan(name string, c chan *[]string) {
	roles := u.GetAttachedRoles(name)
	c <- roles
}

func (u *UserRoleGetter) FetchRoles(name string) *[]string {
	u.Logger.Debugf("In FetchRoles() with param: %s", name)
	roles := make([]string, 0)
	c := make(chan *[]string)

	go u.GetInlineRolesChan(name, c)
	go u.GetAttachedRolesChan(name, c)

	for i := 0; i < 2; i++ {
		r := <-c
		roles = append(roles, *r...)
	}

	u.Logger.Debugf("ALL USER ROLES: %+v", roles)
	return &roles
}

type GroupRoleGetter struct {
	Client *iam.IAM
	Logger *logo.Logger
}

func (g *GroupRoleGetter) GetInlineRoles(name string) *[]string {
	g.Logger.Debugf("In GetInlineRoles() with param: %s", name)
	roles := make([]string, 0)
	listPolInput := iam.ListGroupPoliciesInput{GroupName: &name}
	getPolInput := iam.GetGroupPolicyInput{GroupName: &name}

	truncated := true
	for truncated {
		polList, err := g.Client.ListGroupPolicies(&listPolInput)
		if err != nil {
			g.Logger.Errorf("Error calling ListGroupPolicies(): %v", err)
			break
		}

		for _, p := range polList.PolicyNames {
			getPolInput.PolicyName = p
			res, err := g.Client.GetGroupPolicy(&getPolInput)
			if err != nil {
				g.Logger.Errorf("Error calling GetGroupPolicy(): %v", err)
				continue
			}

			r, err := parsePolicy(res.PolicyDocument)
			if err != nil {
				g.Logger.Errorf("Error parsing policy document: %v", err)
				continue
			}

			roles = append(roles, *r...)
		}

		truncated = *polList.IsTruncated
		if truncated {
			listPolInput.Marker = polList.Marker
		}
	}

	g.Logger.Debugf("GROUP INLINE ROLES: %+v", roles)
	return &roles
}

func (g *GroupRoleGetter) GetAttachedRoles(name string) *[]string {
	g.Logger.Debugf("In GetAttachedRoles() with param: %s", name)
	roles := make([]string, 0)
	listPolInput := iam.ListAttachedGroupPoliciesInput{GroupName: &name}

	truncated := true
	for truncated {
		polList, err := g.Client.ListAttachedGroupPolicies(&listPolInput)
		if err != nil {
			g.Logger.Errorf("Error calling ListAttachedGroupPolicies(): %v", err)
			break
		}

		for _, p := range polList.AttachedPolicies {
			getPolInput := iam.GetPolicyInput{PolicyArn: p.PolicyArn}
			getPolRes, err := g.Client.GetPolicy(&getPolInput)
			if err != nil {
				g.Logger.Errorf("Error calling GetPolicy(): %v", err)
				continue
			}

			getPolVerInput := iam.GetPolicyVersionInput{PolicyArn: getPolRes.Policy.Arn, VersionId: getPolRes.Policy.DefaultVersionId}
			getPolVerRes, err := g.Client.GetPolicyVersion(&getPolVerInput)
			if err != nil {
				g.Logger.Errorf("Error calling GetPolicyVersion(): %v", err)
				continue
			}

			r, err := parsePolicy(getPolVerRes.PolicyVersion.Document)
			if err != nil {
				g.Logger.Errorf("Error parsing policy document: %v", err)
				continue
			}

			roles = append(roles, *r...)
		}

		truncated = *polList.IsTruncated
		if truncated {
			listPolInput.Marker = polList.Marker
		}
	}

	g.Logger.Debug("GROUP ATTACHED ROLES: %+v", roles)
	return &roles
}

func (g *GroupRoleGetter) GetInlineRolesChan(name string, c chan *[]string) {
	roles := g.GetInlineRoles(name)
	c <- roles
}

func (g *GroupRoleGetter) GetAttachedRolesChan(name string, c chan *[]string) {
	roles := g.GetAttachedRoles(name)
	c <- roles
}

func (g *GroupRoleGetter) FetchRoles(groups ...*iam.Group) *[]string {
	g.Logger.Debugf("In FetchRoles() with params: %v", groups)
	roles := make([]string, 0)
	c := make(chan *[]string, 4)

	for _, grp := range groups {
		go g.GetInlineRolesChan(*grp.GroupName, c)
		go g.GetAttachedRolesChan(*grp.GroupName, c)
	}

	for i := 0; i < len(groups)*2; i++ {
		r := <-c
		roles = append(roles, *r...)
	}

	g.Logger.Debugf("ALL GROUP ROLES: %v", roles)
	return &roles
}
