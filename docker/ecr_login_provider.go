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
	"bytes"
	"context"
	"encoding/base64"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/mmmorris1975/aws-runas/shared"
	"os"
	"os/exec"
	"strings"
)

type ecrApi interface {
	GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

type ecrLoginProvider struct {
	ecrClient ecrApi
	logger    shared.Logger
}

// NewEcrLoginProvider creates a valid, default EcrLoginProvider using the specified client.ConfigProvider.
func NewEcrLoginProvider(cfg aws.Config) *ecrLoginProvider {
	return &ecrLoginProvider{
		ecrClient: ecr.NewFromConfig(cfg),
		logger:    new(shared.DefaultLogger),
	}
}

// WithLogger is a fluent method used or setting the logger implementation for the login provider.
func (p *ecrLoginProvider) WithLogger(l shared.Logger) *ecrLoginProvider {
	if l != nil {
		p.logger = l
	}
	return p
}

// Login authenticates to the given ECR endpoints
func (p *ecrLoginProvider) Login(endpoints ...string) error {
	return p.LoginWithContext(context.Background(), endpoints...)
}

// LoginWithContext authenticates to the given ECR endpoints using the provided context
func (p *ecrLoginProvider) LoginWithContext(ctx context.Context, endpoints ...string) error {
	out, err := p.ecrClient.GetAuthorizationToken(ctx, new(ecr.GetAuthorizationTokenInput))
	if err != nil {
		p.logger.Errorf("error calling GeAuthorizationToken: %v", err)
		return err
	}

	var token []byte
	token, err = base64.StdEncoding.DecodeString(*out.AuthorizationData[0].AuthorizationToken)
	if err != nil {
		p.logger.Errorf("error decoding authorization token: %v", err)
		return err
	}

	parts := strings.Split(string(token), `:`)

	for _, ep := range endpoints {
		cmd := exec.Command("docker", "login", "--username", parts[0], "--password-stdin", ep)
		cmd.Stdin = bytes.NewReader([]byte(parts[1]))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		p.logger.Debugf("executing 'docker login' for ECR endpoint: %s", ep)

		err = cmd.Start()
		if err != nil {
			p.logger.Errorf("error running docker login: %v", err)
			return err
		}

		_ = cmd.Wait()
	}

	return nil
}
