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

package docker

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/mmmorris1975/aws-runas/shared"
	"testing"
)

func TestNewEcrLoginProvider(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		p := NewEcrLoginProvider(aws.Config{})
		if p == nil {
			t.Error("nil provider returned")
		}
	})

	t.Run("with logger", func(t *testing.T) {
		p := NewEcrLoginProvider(aws.Config{}).WithLogger(nil)
		if p.logger == nil {
			t.Errorf("data mismatch")
		}
	})
}
func TestEcrLoginProvider_Login(t *testing.T) {
	t.Run("empty endpoint", func(t *testing.T) {
		t.Skip("unable to test due to external requirements")
	})

	t.Run("populated endpoint", func(t *testing.T) {
		t.Skip("unable to test due to external requirements")
	})

	t.Run("error", func(t *testing.T) {
		c := ecrLoginProvider{ecrClient: &mockEcrClient{sendErr: true}, logger: new(shared.DefaultLogger)}
		if err := c.Login("localhost"); err == nil {
			t.Error("did not receive expected error")
		}
	})
}

type mockEcrClient struct {
	ecrApi
	sendErr bool
}

func (c mockEcrClient) GetAuthorizationToken(context.Context, *ecr.GetAuthorizationTokenInput, ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error) {
	if c.sendErr {
		return nil, errors.New("error: GetAuthorizationToken()")
	}

	return &ecr.GetAuthorizationTokenOutput{AuthorizationData: []types.AuthorizationData{
		{AuthorizationToken: aws.String(base64.StdEncoding.EncodeToString([]byte("MOCK:hello world")))},
	}}, nil
}
