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
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/mmmorris1975/aws-runas/credentials/helpers"
	"github.com/mmmorris1975/aws-runas/shared"
	"os"
	"time"
)

type baseStsProvider struct {
	Client        stsApi
	Cache         CredentialCacher
	Duration      time.Duration
	ExpiryWindow  time.Duration
	Logger        shared.Logger
	SerialNumber  string
	TokenCode     string
	TokenProvider func() (string, error)
}

func newBaseStsProvider(cfg aws.Config) *baseStsProvider {
	return &baseStsProvider{
		Client:        sts.NewFromConfig(cfg),
		Logger:        new(shared.DefaultLogger),
		TokenProvider: helpers.NewMfaTokenProvider(os.Stdin).ReadInput,
	}
}

// CheckCache will load credentials from cache.  If a cache is not configured, this method will
// return an empty and expired set of credentials.
func (p *baseStsProvider) CheckCache() *Credentials {
	creds := new(Credentials)

	if p.Cache != nil {
		if creds = p.Cache.Load(); creds.Value().HasKeys() {
			p.Logger.Debugf("loaded sts credentials from cache")
		} else {
			creds.Expiration = time.Unix(0, 0)
		}
	}

	return creds
}

// ConvertDuration normalizes and returns an int64 duration value which is compatible with the AWS
// SDK credential duration field in the API input objects.  The 1st duration argument to this method
// will be checked against the other provided duration values.  If less than 1, the default value will
// be used, if less than the minimum, the minimum value will be used, and if greater than the maximum,
// the maximum value will be used.
func (p *baseStsProvider) ConvertDuration(d, min, max, def time.Duration) *int32 {
	switch {
	case d < 1:
		p.Logger.Debugf("provided duration less than 1, setting to default value")
		d = def
	case d < min:
		p.Logger.Debugf("provided duration too short, setting to minimum value")
		d = min
	case d > max:
		p.Logger.Debugf("provided duration too long, setting to maximum value")
		d = max
	}

	return aws.Int32(int32(d.Seconds()))
}

func (p *baseStsProvider) handleMfa() (*string, error) {
	if len(p.SerialNumber) > 0 {
		if len(p.TokenCode) > 0 {
			return aws.String(p.TokenCode), nil
		}

		// prompt for mfa
		if p.TokenProvider != nil {
			t, err := p.TokenProvider()
			if err != nil {
				return nil, err
			}
			return aws.String(t), nil
		}

		return nil, ErrMfaRequired
	}

	// mfa not required
	return nil, nil
}
