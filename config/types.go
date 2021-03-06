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

import "github.com/mmmorris1975/aws-runas/shared"

var (
	// DefaultLoaderChain is the default loader chain array which will first retrieve values from ini-style configuration
	// sources, then consult environment variables to set (or override) additional configuration.
	DefaultLoaderChain = []Loader{DefaultIniLoader, DefaultEnvLoader}
	// DefaultLoader is the default loader type for loading configuration and credential information, which uses a
	// ChainLoader configured with the DefaultLoaderChain.
	DefaultLoader = NewChainLoader(DefaultLoaderChain)
	// DefaultResolver is the default resolution object for building configuration and credential information.  It uses
	// the DefaultLoader, and will apply values from any source profile to the configuration.
	DefaultResolver = NewResolver(DefaultLoader, true)

	logger shared.Logger = new(shared.DefaultLogger)
)

// EnvLoader defines the methods which can load configuration and credentials from environment variables.
type EnvLoader interface {
	Loader // implemented methods will typically discard input variables and delegate to the appropriate Env*() method
	EnvConfig() (*AwsConfig, error)
	EnvCredentials() (*AwsCredentials, error)
}

// Loader defines the methods which load configuration and credentials for a specified profile from one or more
// implementation specific sources.
type Loader interface {
	Config(profile string, sources ...interface{}) (*AwsConfig, error)
	Credentials(profile string, sources ...interface{}) (*AwsCredentials, error)
}

// Resolver defines the methods for retrieving configuration and credential information using profile names.
type Resolver interface {
	Config(profile string) (*AwsConfig, error)
	Credentials(profile string) (*AwsCredentials, error)
}
