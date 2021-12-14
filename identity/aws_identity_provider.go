/*
 * Copyright (c) 2021 Michael Morris. All Rights Reserved.
 *
 * Licensed under the MIT license (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * https://github.com/mmmorris1975/aws-runas/blob/master/LICENSE
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under the License.
 */

package identity

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/mmmorris1975/aws-runas/shared"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// ProviderAws is the name which names the the provider which resolved the identity.
const ProviderAws = "AwsIdentityProvider"

type awsIdentityProvider struct {
	stsClient StsApi
	iamClient iamApi
	logger    shared.Logger
	wg        *sync.WaitGroup
}

// NewAwsIdentityProvider creates a valid, default AwsIdentityProvider using the specified client.ConfigProvider.
func NewAwsIdentityProvider(cfg aws.Config) *awsIdentityProvider {
	return &awsIdentityProvider{
		stsClient: sts.NewFromConfig(cfg),
		iamClient: iam.NewFromConfig(cfg),
		logger:    new(shared.DefaultLogger),
		wg:        new(sync.WaitGroup),
	}
}

// WithLogger is a fluent method used or setting the logger implementation for the identity provider.
func (p *awsIdentityProvider) WithLogger(l shared.Logger) *awsIdentityProvider {
	if l != nil {
		p.logger = l
	}
	return p
}

// Identity retrieves the Identity information for the AWS IAM user.
func (p *awsIdentityProvider) Identity() (*Identity, error) {
	out, err := p.stsClient.GetCallerIdentity(context.Background(), new(sts.GetCallerIdentityInput))
	if err != nil {
		p.logger.Errorf("error calling GetCallerIdentity: %v", err)
		return nil, err
	}

	// pretty sure this will always be valid if GetCallerIdentity() succeeds
	a, _ := arn.Parse(*out.Arn)
	// if err != nil {
	//	p.logger.Errorf("error parsing identity ARN: %v", err)
	//	return nil, err
	// }

	id := &Identity{Provider: ProviderAws}

	r := strings.Split(a.Resource, "/")
	id.IdentityType = r[0]
	id.Username = r[len(r)-1]

	return id, nil
}

// Roles retrieves the roles which the identity is able to assume.
//
// This method will check the inline and attached IAM policies for the user, and any groups the user is a member of.
// It will return all roles the user is allowed to assume, even those specifying wildcards in the ARN fields.
func (p *awsIdentityProvider) Roles(user ...string) (*Roles, error) {
	if user == nil || len(user) < 1 || len(user[0]) < 1 {
		id, err := p.Identity()
		if err != nil {
			return nil, err
		}
		user = []string{id.Username}
	}

	ch := make(chan string, 32)
	m := make(map[string]bool) // data deduplication

	go p.roles(user[0], ch)
	for e := range ch {
		tr := strings.TrimSpace(e)
		if len(tr) > 0 {
			m[tr] = true
			p.logger.Debugf("found role ARN: %s", tr)
		}
	}

	i := 0
	roles := make([]string, len(m))
	for k := range m {
		roles[i] = k
		i++
	}

	sort.Strings(roles)
	r := Roles(roles)
	return &r, nil
}

func (p *awsIdentityProvider) roles(user string, ch chan<- string) {
	defer close(ch)

	p.wg.Add(2)
	go p.getInlineUserRoles(user, ch)
	go p.getAttachedUserRoles(user, ch)

	var err error
	in := &iam.ListGroupsForUserInput{UserName: aws.String(user)}
	pg := iam.NewListGroupsForUserPaginator(p.iamClient, in)
	for pg.HasMorePages() {
		out, e := pg.NextPage(context.Background())
		if e != nil {
			err = e
			continue
		}

		for _, g := range out.Groups {
			p.logger.Debugf("GROUP: %s", *g.GroupName)
			p.wg.Add(2)
			go p.getInlineGroupRoles(*g.GroupName, ch)
			go p.getAttachedGroupRoles(*g.GroupName, ch)
		}
	}

	if err != nil {
		p.logger.Errorf("error getting IAM group list for %s: %v", user, err)
	}

	p.wg.Wait()
}

func (p *awsIdentityProvider) getInlineUserRoles(user string, ch chan<- string) {
	defer p.wg.Done()

	var err error
	lIn := &iam.ListUserPoliciesInput{UserName: aws.String(user)}
	pIn := &iam.GetUserPolicyInput{UserName: aws.String(user)}
	pg := iam.NewListUserPoliciesPaginator(p.iamClient, lIn)
	for pg.HasMorePages() {
		out, e := pg.NextPage(context.Background())
		if e != nil {
			err = e
			continue
		}

		for _, pol := range out.PolicyNames {
			pIn.PolicyName = aws.String(pol)

			r, e := p.iamClient.GetUserPolicy(context.Background(), pIn)
			if e != nil {
				p.logger.Errorf("error getting policy %s for user %s: %v", pol, user, e)
				continue
			}

			p.findPolicyRoles(r.PolicyDocument, ch)
		}
	}

	if err != nil {
		p.logger.Errorf("error getting inline policies for user %s: %v", user, err)
	}
}

func (p *awsIdentityProvider) getAttachedUserRoles(user string, ch chan<- string) {
	defer p.wg.Done()

	var err error
	in := &iam.ListAttachedUserPoliciesInput{UserName: aws.String(user)}
	pg := iam.NewListAttachedUserPoliciesPaginator(p.iamClient, in)
	for pg.HasMorePages() {
		out, e := pg.NextPage(context.Background())
		if e != nil {
			err = e
			continue
		}

		for _, pol := range out.AttachedPolicies {
			p.getAttachedPolicyRoles(pol.PolicyArn, ch)
		}
	}

	if err != nil {
		p.logger.Errorf("error getting attached policies for user %s: %v", user, err)
	}
}

func (p *awsIdentityProvider) getInlineGroupRoles(group string, ch chan<- string) {
	defer p.wg.Done()

	var err error
	lIn := &iam.ListGroupPoliciesInput{GroupName: aws.String(group)}
	pIn := &iam.GetGroupPolicyInput{GroupName: aws.String(group)}
	pg := iam.NewListGroupPoliciesPaginator(p.iamClient, lIn)
	for pg.HasMorePages() {
		out, e := pg.NextPage(context.Background())
		if e != nil {
			err = e
			continue
		}

		for _, pol := range out.PolicyNames {
			pIn.PolicyName = aws.String(pol)

			r, e := p.iamClient.GetGroupPolicy(context.Background(), pIn)
			if e != nil {
				p.logger.Errorf("error getting policy %s for group %s: %v", pol, group, e)
				continue
			}

			p.findPolicyRoles(r.PolicyDocument, ch)
		}
	}

	if err != nil {
		p.logger.Errorf("error getting inline policies for group %s: %v", group, err)
	}
}

func (p *awsIdentityProvider) getAttachedGroupRoles(group string, ch chan<- string) {
	defer p.wg.Done()

	var err error
	in := &iam.ListAttachedGroupPoliciesInput{GroupName: aws.String(group)}
	pg := iam.NewListAttachedGroupPoliciesPaginator(p.iamClient, in)
	for pg.HasMorePages() {
		out, e := pg.NextPage(context.Background())
		if e != nil {
			err = e
			continue
		}

		for _, pol := range out.AttachedPolicies {
			p.getAttachedPolicyRoles(pol.PolicyArn, ch)
		}
	}

	if err != nil {
		p.logger.Errorf("error getting attached policies for group %s: %v", group, err)
	}
}

func (p *awsIdentityProvider) getAttachedPolicyRoles(arn *string, ch chan<- string) {
	pol, err := p.iamClient.GetPolicy(context.Background(), &iam.GetPolicyInput{PolicyArn: arn})
	if err != nil {
		p.logger.Errorf("error getting IAM policy %s: %v", *arn, err)
		return
	}

	vIn := &iam.GetPolicyVersionInput{PolicyArn: pol.Policy.Arn, VersionId: pol.Policy.DefaultVersionId}
	ver, err := p.iamClient.GetPolicyVersion(context.Background(), vIn)
	if err != nil {
		p.logger.Errorf("error getting IAM policy version for policy %s: %v", *pol.Policy.PolicyName, err)
		return
	}

	p.findPolicyRoles(ver.PolicyVersion.Document, ch)
}

func (p *awsIdentityProvider) findPolicyRoles(doc *string, ch chan<- string) {
	if doc == nil || len(*doc) < 1 {
		p.logger.Errorf("empty policy document")
		return
	}

	escDoc, err := url.QueryUnescape(*doc)
	if err != nil {
		p.logger.Errorf("error unescaping policy document: %v", err)
		return
	}

	polJson := make(map[string]interface{})
	if err := json.Unmarshal([]byte(escDoc), &polJson); err != nil {
		p.logger.Errorf("error unmarshalling policy document json: %v", err)
		return
	}

	for _, r := range p.findRoles(polJson["Statement"]) {
		ch <- r
	}
}

//nolint:gocognit // Thanks AWS for letting the Action be either a string or an []interface{}
func (p *awsIdentityProvider) findRoles(data interface{}) []string {
	roles := make([]string, 0)

	switch t := data.(type) {
	case []interface{}:
		for _, v := range t {
			roles = append(roles, p.findRoles(v)...)
		}
	case map[string]interface{}:
		assumeRoleAction := "sts:AssumeRole"

		if t["Effect"] == "Allow" {
			switch v := t["Action"].(type) {
			case string:
				if v == assumeRoleAction {
					roles = append(roles, p.parseRoles(t["Resource"])...)
				}
			case []interface{}:
				for _, val := range v {
					if val == assumeRoleAction {
						roles = append(roles, p.parseRoles(t["Resource"])...)
					}
				}
			}
		}
	}

	return roles
}

func (p *awsIdentityProvider) parseRoles(data interface{}) []string {
	roles := make([]string, 0)

	switch r := data.(type) {
	case string:
		if p.isRoleArn(r) {
			roles = append(roles, r)
		}
	case []interface{}:
		for _, i := range r {
			if p.isRoleArn(i.(string)) {
				roles = append(roles, i.(string))
			}
		}
	}

	return roles
}

func (p *awsIdentityProvider) isRoleArn(s string) bool {
	if s == "*" {
		return true
	}

	a, err := arn.Parse(s)
	if err != nil {
		p.logger.Errorf("error parsing ARN %s: %v", s, err)
		return false
	}

	if a.Service == "iam" && strings.HasPrefix(a.Resource, "role/") {
		return true
	}

	return false
}
