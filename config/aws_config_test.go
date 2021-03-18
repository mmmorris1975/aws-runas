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
	"os"
	"testing"
	"time"
)

func TestAwsConfig_MergeIn(t *testing.T) {
	// just here for some cheap coverage numbers
	new(AwsConfig).MergeIn(&AwsConfig{
		CredentialsDuration:    6 * time.Hour,
		SessionTokenDuration:   24 * time.Hour,
		DurationSeconds:        5400,
		ExternalId:             "ext",
		MfaSerial:              "mfa",
		MfaCode:                "code",
		MfaType:                "auto",
		Region:                 "region",
		RoleArn:                "role",
		RoleSessionName:        "name",
		SrcProfile:             "src",
		JumpRoleArn:            "jump",
		SamlUrl:                "saml",
		SamlUsername:           "user",
		SamlProvider:           "saml",
		WebIdentityUrl:         "web",
		WebIdentityUsername:    "user",
		WebIdentityProvider:    "web",
		WebIdentityTokenFile:   os.DevNull,
		WebIdentityClientId:    "oauth_client",
		WebIdentityRedirectUri: "app:/callback",
		FederatedUsername:      "fed",
		sourceProfile:          nil,
	})
}

func TestAwsConfig_Validate(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		if err := new(AwsConfig).Validate(); err != nil {
			t.Error(err)
		}
	})

	t.Run("bad source profile", func(t *testing.T) {
		if err := (&AwsConfig{SrcProfile: "test"}).Validate(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("saml and oidc urls", func(t *testing.T) {
		cfg := &AwsConfig{
			SamlUrl:        "http://localhost/saml",
			WebIdentityUrl: "http://localhost/oidc",
		}

		if err := cfg.Validate(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("missing oidc client id", func(t *testing.T) {
		cfg := &AwsConfig{
			WebIdentityUrl:         "http://localhost/oidc",
			WebIdentityRedirectUri: "app:/callback",
		}

		if err := cfg.Validate(); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("missing oidc redirect uri", func(t *testing.T) {
		cfg := &AwsConfig{
			WebIdentityUrl:      "http://localhost/oidc",
			WebIdentityClientId: "MyClientId",
		}

		if err := cfg.Validate(); err == nil {
			t.Error("did not receive expected error")
		}
	})
}
