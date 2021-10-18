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

package credentials

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"time"
)

// Credentials is a generic credential type which contains the necessary information to provide formatting and
// transformation to describe EC2 and ECS metadata credentials, credential process credentials, the credentials.Value
// type, the sts.Credentials type, and a map which can be used to set credentials via environment variables.
type Credentials struct {
	AccessKeyId     string     `ini:"aws_access_key_id" env:"AWS_ACCESS_KEY_ID"`
	SecretAccessKey string     `ini:"aws_secret_access_key" env:"AWS_SECRET_ACCESS_KEY"`
	Token           string     `json:",omitempty" ini:"aws_session_token,omitempty" env:"AWS_SESSION_TOKEN,omitempty"`
	Expiration      time.Time  `ini:"-" env:"-"`
	Code            string     `json:",omitempty" ini:"-" env:"-"` // only used with EC2 credentials
	Type            string     `json:",omitempty" ini:"-" env:"-"` // only used with EC2 credentials
	LastUpdated     *time.Time `json:",omitempty" ini:"-" env:"-"` // only used with EC2 credentials
	ProviderName    string     `json:"-" ini:"-" env:"-"`          // only used for Value()
}

// ProcessCredentials is a specific type of credentials used for the credential process credential type.
type ProcessCredentials struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string     `json:",omitempty"`
	Version         int        // required, only valid value is currently 1
	Expiration      *time.Time `json:",omitempty"` // must be a pointer, otherwise it Marshals a zero-value time.Time
}

// EC2 returns the credentials as JSON bytes which conform to the format used by the EC2 metadata service (IMDS)
// More info can be found at
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials.
func (c *Credentials) EC2() ([]byte, error) {
	// ideally is already set, but just to be sure
	if len(c.Code) < 1 {
		c.Code = "Success"
	}

	c.Type = "AWS-HMAC"                        // constant
	c.LastUpdated = aws.Time(time.Now().UTC()) // could this be smarter? (it's worked out alright so far)
	return json.Marshal(c)
}

// ECS returns the credentials as JSON bytes which conform to the format used by the ECS metadata service
// More info can be found at https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html.
func (c *Credentials) ECS() ([]byte, error) {
	return json.Marshal(c)
}

// Env returns a map of environment variable names and values which can be used to set the credentials as environment
// variables.
func (c *Credentials) Env() map[string]string {
	m := make(map[string]string)
	m["AWS_ACCESS_KEY_ID"] = c.AccessKeyId
	m["AWS_SECRET_ACCESS_KEY"] = c.SecretAccessKey

	if len(c.Token) > 0 {
		m["AWS_SESSION_TOKEN"] = c.Token
		m["AWS_SECURITY_TOKEN"] = c.Token
	}

	return m
}

// CredentialsProcess returns the credentials as JSON bytes which conform to the format used for the credential process
// feature. If the Expiration field is not set, the credentials will be treated as non-expiring, and will not be
// automatically refreshed. More info can be found at
// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html.
func (c *Credentials) CredentialsProcess() ([]byte, error) {
	pc := ProcessCredentials{
		AccessKeyId:     c.AccessKeyId,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.Token,
		Version:         1,
	}

	if !c.Expiration.IsZero() {
		pc.Expiration = aws.Time(c.Expiration)
	}

	return json.Marshal(&pc)
}

// Value returns an aws.Credentials type for programmatic use.
// AWS SDK v1 terminology retained due to laziness.
func (c *Credentials) Value() aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     c.AccessKeyId,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.Token,
		Source:          c.ProviderName,
		Expires:         c.Expiration,
		CanExpire:       true,
	}
}

// StsCredentials returns an AWS sts.Credentials type for programmatic use. Also suitable for long term caching.
func (c *Credentials) StsCredentials() *types.Credentials {
	return &types.Credentials{
		AccessKeyId:     aws.String(c.AccessKeyId),
		Expiration:      aws.Time(c.Expiration),
		SecretAccessKey: aws.String(c.SecretAccessKey),
		SessionToken:    aws.String(c.Token),
	}
}

// FromValue provides a way to take an aws.Credentials type and convert it to a Credentials type.
// Since expiration information is not a native part of the AWS credentials.Value type, it should
// be set manually in the Expiration field on the returned object, using data sourced elsewhere.
// AWS SDK v1 terminology retained due to laziness.
func FromValue(v aws.Credentials) *Credentials {
	return &Credentials{
		AccessKeyId:     v.AccessKeyID,
		SecretAccessKey: v.SecretAccessKey,
		Token:           v.SessionToken,
		ProviderName:    v.Source,
		Expiration:      v.Expires,
	}
}

// FromStsCredentials provides a way to take an AWS sts.Credentials and convert it to a Credentials type.
// Since credential provider information is not a native part of the AWS sts.Credentials type, it should
// be set manually in the ProviderName field on the returned object, using data sourced elsewhere.
func FromStsCredentials(v *types.Credentials) *Credentials {
	c := new(Credentials)

	if v == nil {
		return c
	}

	if v.AccessKeyId != nil {
		c.AccessKeyId = *v.AccessKeyId
	}

	if v.SecretAccessKey != nil {
		c.SecretAccessKey = *v.SecretAccessKey
	}

	if v.SessionToken != nil {
		c.Token = *v.SessionToken
	}

	if v.Expiration != nil {
		c.Expiration = *v.Expiration
	}

	return c
}
