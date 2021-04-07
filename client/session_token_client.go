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

package client

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/shared"
	"time"
)

type sessionTokenClient struct {
	*baseIamClient
	provider *credentials.SessionTokenProvider
}

// SessionTokenClientConfig is the configuration attributes for the STS GetSessionToken operation for IAM identities.
type SessionTokenClientConfig struct {
	Cache         credentials.CredentialCacher
	Logger        shared.Logger
	Duration      time.Duration
	SerialNumber  string
	TokenCode     string
	TokenProvider func() (string, error)
}

// NewSessionTokenClient is an AwsClient which knows how to do Get Session Token operations.
func NewSessionTokenClient(cfg aws.Config, clientCfg *SessionTokenClientConfig) *sessionTokenClient {
	c := &sessionTokenClient{newBaseIamClient(cfg, clientCfg.Logger), nil}

	p := credentials.NewSessionTokenProvider(cfg)
	p.Cache = clientCfg.Cache
	p.Duration = clientCfg.Duration
	p.SerialNumber = clientCfg.SerialNumber
	p.TokenCode = clientCfg.TokenCode
	p.TokenProvider = clientCfg.TokenProvider
	p.Logger = clientCfg.Logger

	c.provider = p
	c.creds = aws.NewCredentialsCache(p)
	return c
}

// ClearCache cleans the cache for this client's AWS credential cache.
func (c *sessionTokenClient) ClearCache() error {
	if c.creds != nil {
		c.creds.Invalidate()
	}

	if c.provider.Cache != nil {
		c.provider.Logger.Debugf("clearing cached session token credentials")
		return c.provider.Cache.Clear()
	}
	return nil
}

// I can't remember why we added this, and it seems to be unhelpful.
// func (c *sessionTokenClient) ExpiresAt() time.Time {
//	return time.Time{}
// }
