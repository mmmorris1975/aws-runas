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

package config

import (
	"errors"
	"time"
)

type badLoader bool

func (l *badLoader) Config(string, ...interface{}) (*AwsConfig, error) {
	return nil, errors.New("bad config")
}

func (l *badLoader) Credentials(string, ...interface{}) (*AwsCredentials, error) {
	return nil, errors.New("bad credentials")
}

type simpleLoader bool

func (l *simpleLoader) Config(string, ...interface{}) (*AwsConfig, error) {
	c := &AwsConfig{
		Region: "mockRegion",
	}
	return c, nil
}

func (l *simpleLoader) Credentials(string, ...interface{}) (*AwsCredentials, error) {
	return new(AwsCredentials), nil
}

type samlLoader bool

func (l *samlLoader) Config(string, ...interface{}) (*AwsConfig, error) {
	c := &AwsConfig{
		CredentialsDuration: 1 * time.Hour,
		RoleArn:             "mockRole",
		SamlUrl:             "https://saml.local/saml",
		SamlUsername:        "mockUser",
	}
	return c, nil
}

func (l *samlLoader) Credentials(string, ...interface{}) (*AwsCredentials, error) {
	return &AwsCredentials{SamlPassword: "mockPassword"}, nil
}

type sourceProfileLoader bool

func (l *sourceProfileLoader) Config(string, ...interface{}) (*AwsConfig, error) {
	src := &AwsConfig{
		CredentialsDuration: 4 * time.Hour,
		MfaSerial:           "mockMfa",
		Region:              "mockRegion",
	}
	c := &AwsConfig{
		ExternalId:    "mockExtId",
		RoleArn:       "mockRole",
		SrcProfile:    "mock",
		sourceProfile: src,
	}
	return c, nil
}

func (l *sourceProfileLoader) Credentials(string, ...interface{}) (*AwsCredentials, error) {
	return new(AwsCredentials), nil
}
