package identity

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// ProviderAws is the name which names the the provider which resolved the identity
const ProviderAws = "AwsIdentityProvider"

// AwsIdentityProvider gets identity information for AWS IAM users
type AwsIdentityProvider struct {
	iamClient iamiface.IAMAPI
	stsClient stsiface.STSAPI
	log       aws.Logger
	logDebug  bool
	wg        *sync.WaitGroup
}

// NewAwsIdentityProvider creates a valid, default AwsIdentityProvider using the specified client.ConfigProvider
func NewAwsIdentityProvider(c client.ConfigProvider) *AwsIdentityProvider {
	return &AwsIdentityProvider{
		stsClient: sts.New(c),
		iamClient: iam.New(c),
		log:       aws.NewDefaultLogger(),
		logDebug:  c.ClientConfig("sts").Config.LogLevel.AtLeast(aws.LogDebug),
		wg:        new(sync.WaitGroup),
	}
}

// WithLogger is a fluent method to configure a logger for the AwsIdentityProvider
func (p *AwsIdentityProvider) WithLogger(l aws.Logger) *AwsIdentityProvider {
	p.log = l
	return p
}

// GetIdentity retrieves the Identity information for the IAM user
func (p *AwsIdentityProvider) GetIdentity() (*Identity, error) {
	o, err := p.stsClient.GetCallerIdentity(new(sts.GetCallerIdentityInput))
	if err != nil {
		p.debug("error calling GetCallerIdentity: %v", err)
		return nil, err
	}

	a, err := arn.Parse(*o.Arn)
	if err != nil {
		p.debug("error parsing identity ARN: %v", err)
		return nil, err
	}

	id := &Identity{Provider: ProviderAws}

	r := strings.Split(a.Resource, "/")
	id.IdentityType = r[0]
	id.Username = r[len(r)-1]

	return id, nil
}

// Roles retrieves the roles which the user is able to assume.  The user parameter is the IAM user name of the user to
// fetch roles for.  If this value is nil or empty, then the identity information will be determined by calling
// GetIdentity().
//
// This method will check the inline and attached IAM policies for the user, and any groups the user is a member of.  It
// will return all roles the user is allowed to assume, even those specifying wildcards in the ARN fields.
func (p *AwsIdentityProvider) Roles(user ...string) (Roles, error) {
	if user == nil || len(user) < 1 || len(user[0]) < 1 {
		id, err := p.GetIdentity()
		if err != nil {
			return nil, err
		}
		user = []string{id.Username}
	}

	m := make(map[string]bool)
	ch := make(chan string, 8)

	go p.roles(user[0], ch)
	for i := range ch {
		tr := strings.TrimSpace(i)
		if len(tr) > 0 {
			m[tr] = true
			p.debug("found role ARN: %s", tr)
		}
	}

	r := make([]string, 0)
	for k := range m {
		r = append(r, k)
	}

	sort.Strings(r)
	return r, nil
}

func (p *AwsIdentityProvider) roles(user string, ch chan<- string) {
	defer close(ch)

	p.wg.Add(2)
	go p.getInlineUserRoles(user, ch)
	go p.getAttachedUserRoles(user, ch)

	in := new(iam.ListGroupsForUserInput).SetUserName(user)
	err := p.iamClient.ListGroupsForUserPages(in, func(out *iam.ListGroupsForUserOutput, last bool) bool {
		for _, g := range out.Groups {
			p.debug("GROUP: %s", *g.GroupName)
			p.wg.Add(2)
			go p.getInlineGroupRoles(*g.GroupName, ch)
			go p.getAttachedGroupRoles(*g.GroupName, ch)
		}

		return !last
	})

	if err != nil {
		p.error("error getting IAM group list for %s: %v", user, err)
	}

	p.wg.Wait()
}

func (p *AwsIdentityProvider) getInlineUserRoles(user string, ch chan<- string) {
	defer p.wg.Done()

	in := new(iam.ListUserPoliciesInput).SetUserName(user)
	pIn := new(iam.GetUserPolicyInput).SetUserName(user)

	err := p.iamClient.ListUserPoliciesPages(in, func(out *iam.ListUserPoliciesOutput, last bool) bool {
		for _, pol := range out.PolicyNames {
			pIn.PolicyName = pol

			r, err := p.iamClient.GetUserPolicy(pIn)
			if err != nil {
				p.error("error getting policy %s for user %s: %v", *pol, user, err)
				continue
			}

			p.findPolicyRoles(r.PolicyDocument, ch)
		}

		return !last
	})

	if err != nil {
		p.error("error getting inline policies for user %s: %v", user, err)
	}
}

func (p *AwsIdentityProvider) getAttachedUserRoles(user string, ch chan<- string) {
	defer p.wg.Done()

	in := new(iam.ListAttachedUserPoliciesInput).SetUserName(user)

	err := p.iamClient.ListAttachedUserPoliciesPages(in, func(out *iam.ListAttachedUserPoliciesOutput, last bool) bool {
		for _, pol := range out.AttachedPolicies {
			p.getAttachedPolicyRoles(pol.PolicyArn, ch)
		}

		return !last
	})

	if err != nil {
		p.error("error getting attached policies for user %s: %v", user, err)
	}
}

func (p *AwsIdentityProvider) getInlineGroupRoles(group string, ch chan<- string) {
	defer p.wg.Done()

	in := new(iam.ListGroupPoliciesInput).SetGroupName(group)
	pIn := new(iam.GetGroupPolicyInput).SetGroupName(group)

	err := p.iamClient.ListGroupPoliciesPages(in, func(out *iam.ListGroupPoliciesOutput, last bool) bool {
		for _, pol := range out.PolicyNames {
			pIn.PolicyName = pol

			r, err := p.iamClient.GetGroupPolicy(pIn)
			if err != nil {
				p.error("error getting policy %s for group %s: %v", *pol, group, err)
				continue
			}

			p.findPolicyRoles(r.PolicyDocument, ch)
		}

		return !last
	})

	if err != nil {
		p.error("error getting inline policies for group %s: %v", group, err)
	}
}

func (p *AwsIdentityProvider) getAttachedGroupRoles(group string, ch chan<- string) {
	defer p.wg.Done()

	in := new(iam.ListAttachedGroupPoliciesInput).SetGroupName(group)
	err := p.iamClient.ListAttachedGroupPoliciesPages(in, func(out *iam.ListAttachedGroupPoliciesOutput, last bool) bool {
		for _, pol := range out.AttachedPolicies {
			p.getAttachedPolicyRoles(pol.PolicyArn, ch)
		}

		return !last
	})

	if err != nil {
		p.error("error getting attached policies for group %s: %v", group, err)
	}
}

func (p *AwsIdentityProvider) getAttachedPolicyRoles(arn *string, ch chan<- string) {
	getPol := new(iam.GetPolicyInput).SetPolicyArn(*arn)
	pol, err := p.iamClient.GetPolicy(getPol)
	if err != nil {
		p.error("error getting IAM policy %s: %v", *arn, err)
		return
	}

	getVer := new(iam.GetPolicyVersionInput).SetPolicyArn(*pol.Policy.Arn).SetVersionId(*pol.Policy.DefaultVersionId)
	ver, err := p.iamClient.GetPolicyVersion(getVer)
	if err != nil {
		p.error("error getting IAM policy version for policy %s: %v", *pol.Policy.PolicyName, err)
		return
	}

	p.findPolicyRoles(ver.PolicyVersion.Document, ch)
}

func (p *AwsIdentityProvider) findPolicyRoles(doc *string, ch chan<- string) {
	if doc == nil || len(*doc) < 1 {
		p.error("empty policy document")
		return
	}

	escDoc, err := url.QueryUnescape(*doc)
	if err != nil {
		p.error("error unescaping policy document: %v", err)
		return
	}

	polJson := make(map[string]interface{})
	if err := json.Unmarshal([]byte(escDoc), &polJson); err != nil {
		p.error("error unmarshalling policy document json: %v", err)
		return
	}

	for _, r := range p.findRoles(polJson["Statement"]) {
		ch <- r
	}
}

func (p *AwsIdentityProvider) findRoles(data interface{}) []string {
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

func (p *AwsIdentityProvider) parseRoles(data interface{}) []string {
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

func (p *AwsIdentityProvider) isRoleArn(s string) bool {
	if s == "*" {
		return true
	}

	a, err := arn.Parse(s)
	if err != nil {
		p.error("error parsing ARN %s: %v", s, err)
		return false
	}

	if a.Service == "iam" && strings.HasPrefix(a.Resource, "role/") {
		return true
	}

	return false
}

func (p *AwsIdentityProvider) debug(f string, v ...interface{}) {
	if p.logDebug && p.log != nil {
		p.log.Log(fmt.Sprintf(f, v...))
	}
}

func (p *AwsIdentityProvider) error(f string, v ...interface{}) {
	if p.log != nil {
		p.log.Log(fmt.Sprintf(f, v...))
	}
}
