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

package cli

import (
	"context"
	"errors"
	"flag"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/mmmorris1975/aws-runas/config"
	"github.com/mmmorris1975/aws-runas/identity"
	"github.com/urfave/cli/v2"
	"os"
	"testing"
)

func TestListMfaCmd_Action(t *testing.T) {
	configResolver = new(mockConfigResolver)
	ctx := cli.NewContext(App, new(flag.FlagSet), nil)

	t.Run("saml", func(t *testing.T) {
		_ = os.Setenv("AWS_PROFILE", "saml")
		defer os.Unsetenv("AWS_PROFILE")

		if err := mfaCmd.Run(ctx); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("oidc", func(t *testing.T) {
		_ = os.Setenv("AWS_PROFILE", "oidc")
		defer os.Unsetenv("AWS_PROFILE")

		if err := mfaCmd.Run(ctx); err == nil {
			t.Error("did not receive expected error")
		}
	})

	t.Run("arn", func(t *testing.T) {
		_ = os.Setenv("AWS_PROFILE", "arn:aws:iam::0123456789:role/my_role")
		defer os.Unsetenv("AWS_PROFILE")

		if err := mfaCmd.Run(ctx); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

func TestListMfaCmd_getIdentity(t *testing.T) {
	cfg := &config.AwsConfig{
		SamlUrl:      "http://mock.local/saml",
		SamlUsername: "mockUser",
		SamlProvider: "mock",
	}

	if _, err := getIdentity(cfg); err != nil {
		t.Error(err)
	}
}

func TestListMfaCmd_listMfa(t *testing.T) {
	t.Run("user", func(t *testing.T) {
		_ = listMfa(new(mockIam), &identity.Identity{IdentityType: "user"})
	})

	t.Run("not user", func(t *testing.T) {
		if err := listMfa(nil, &identity.Identity{IdentityType: "notuser"}); err != nil {
			t.Error(err)
		}
	})

	t.Run("bad", func(t *testing.T) {
		var c mockIam = true
		if err := listMfa(&c, &identity.Identity{IdentityType: "user"}); err == nil {
			t.Error(err)
		}
	})
}

func Test_getSharedProfile(t *testing.T) {
	t.Run("with SrcProfile", func(t *testing.T) {
		cfg := &config.AwsConfig{SrcProfile: "my_src", ProfileName: "my_profile"}
		if getSharedProfile(cfg) != "my_src" {
			t.Error("data mismatch")
		}
	})

	t.Run("no SrcProfile", func(t *testing.T) {
		cfg := &config.AwsConfig{ProfileName: "my_profile"}
		if getSharedProfile(cfg) != "my_profile" {
			t.Error("data mismatch")
		}
	})
}

type mockIam bool

func (m *mockIam) ListMFADevices(context.Context, *iam.ListMFADevicesInput, ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	if *m {
		return nil, errors.New("failed")
	}

	return new(iam.ListMFADevicesOutput), nil
}
