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
	"fmt"
	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/urfave/cli/v2"
	"os"
	"path/filepath"
)

var shortcutFlags = []cli.Flag{mfaFlag, rolesFlag, updateFlag, diagFlag, vFlag}
var otherFlags = []cli.Flag{envFlag, fmtFlag, sessionFlag, refreshFlag, expFlag, whoamiFlag}
var configFlags = []cli.Flag{sessionDurationFlag, roleDurationFlag, mfaCodeFlag, mfaSerialFlag, mfaTypeFlag, externalIdFlag,
	jumpRoleFlag, samlUrlFlag, oidcUrlFlag, oidcRedirectFlag, oidcClientIdFlag, usernameFlag, passwordFlag, providerFlag}

/*
 * Shortcut flags - perform some non-role credentialed action and exits.
 */
var mfaFlag = &cli.BoolFlag{
	Name:    "list-mfa",
	Aliases: []string{"m"},
	Usage:   "list the ARN of the MFA device associated with your IAM account",
}

var rolesFlag = &cli.BoolFlag{
	Name:    "list-roles",
	Aliases: []string{"l"},
	Usage:   "list role ARNs you are able to assume",
}

var updateFlag = &cli.BoolFlag{
	Name:    "update",
	Aliases: []string{"u"},
	Usage:   fmt.Sprintf("check for updates to %s", filepath.Base(os.Args[0])),
}

var diagFlag = &cli.BoolFlag{
	Name:    "diagnose",
	Aliases: []string{"D"},
	Usage:   "run diagnostics to gather information to aid in troubleshooting",
}

/*
 * Config flags - affect/override resolved configuration values.
 */
var sessionDurationFlag = &cli.DurationFlag{
	Name:        "duration",
	Aliases:     []string{"d"},
	Usage:       "duration of the retrieved session token",
	EnvVars:     []string{"SESSION_TOKEN_DURATION"},
	DefaultText: fmt.Sprintf("%d hours", int64(credentials.SessionTokenDurationDefault.Hours())),
	Destination: &cmdlineCfg.SessionTokenDuration,
}

var roleDurationFlag = &cli.DurationFlag{
	Name:        "role-duration",
	Aliases:     []string{"a"},
	Usage:       "duration of the assume role credentials",
	EnvVars:     []string{"CREDENTIALS_DURATION"},
	DefaultText: fmt.Sprintf("%d hours", int64(credentials.AssumeRoleDurationDefault.Hours())),
	Destination: &cmdlineCfg.CredentialsDuration,
}

var mfaCodeFlag = &cli.StringFlag{
	Name:        "otp",
	Aliases:     []string{"o"},
	Usage:       "MFA token code",
	EnvVars:     []string{"MFA_CODE"},
	Destination: &cmdlineCfg.MfaCode,
}

var mfaSerialFlag = &cli.StringFlag{
	Name:        "mfa-serial",
	Aliases:     []string{"M"},
	Usage:       "serial number (or AWS ARN) of MFA device needed to assume role",
	EnvVars:     []string{"MFA_SERIAL"},
	Destination: &cmdlineCfg.MfaSerial,
}

var mfaTypeFlag = &cli.StringFlag{
	Name:        "mfa-type",
	Aliases:     []string{"t"},
	Usage:       "use specific MFA type instead of provider auto-detection logic",
	EnvVars:     []string{"MFA_TYPE"},
	Destination: &cmdlineCfg.MfaType,
}

var externalIdFlag = &cli.StringFlag{
	Name:        "external-id",
	Aliases:     []string{"X"},
	Usage:       "external ID to use with Assume Role",
	EnvVars:     []string{"EXTERNAL_ID"},
	Destination: &cmdlineCfg.ExternalId,
}

var jumpRoleFlag = &cli.StringFlag{
	Name:        "jump-role",
	Aliases:     []string{"J"},
	Usage:       "ARN of the 'jump role' to use with SAML or Web Identity integration",
	EnvVars:     []string{"JUMP_ROLE_ARN"},
	Destination: &cmdlineCfg.JumpRoleArn,
}

var samlUrlFlag = &cli.StringFlag{
	Name:        "saml-url",
	Aliases:     []string{"S"},
	Usage:       "URL of the SAML authentication endpoint",
	EnvVars:     []string{"SAML_AUTH_URL"},
	Destination: &cmdlineCfg.SamlUrl,
}

var oidcUrlFlag = &cli.StringFlag{
	Name:        "web-url",
	Aliases:     []string{"W"},
	Usage:       "URL of the Web Identity (OIDC) authentication endpoint",
	EnvVars:     []string{"WEB_AUTH_URL"},
	Destination: &cmdlineCfg.WebIdentityUrl,
}

var oidcRedirectFlag = &cli.StringFlag{
	Name:        "web-redirect",
	Aliases:     []string{"T"},
	Usage:       "Web Identity (OIDC) redirect URI",
	EnvVars:     []string{"WEB_REDIRECT_URI"},
	Destination: &cmdlineCfg.WebIdentityRedirectUri,
}

var oidcClientIdFlag = &cli.StringFlag{
	Name:        "web-client",
	Aliases:     []string{"C"},
	Usage:       "Web Identity (OIDC) client ID",
	EnvVars:     []string{"WEB_CLIENT_ID"},
	Destination: &cmdlineCfg.WebIdentityClientId,
}

// Does not have a Destination, set in the App's Before attribute for both SAML and OIDC
// remove the old --saml-user flag, but keep the env var for compatibility.
var usernameFlag = &cli.StringFlag{
	Name:    "username",
	Aliases: []string{"U"},
	Usage:   "username for SAML or Web Identity (OIDC) authentication",
	EnvVars: []string{"RUNAS_USERNAME", "SAML_USERNAME", "WEB_USERNAME"},
}

// Does not have a Destination, set in the App's Before attribute for both SAML and OIDC
// remove the old --saml-password flag, but keep the env var for compatibility.
var passwordFlag = &cli.StringFlag{
	Name:    "password",
	Aliases: []string{"P"},
	Usage:   "password for SAML or Web Identity (OIDC) authentication",
	EnvVars: []string{"RUNAS_PASSWORD", "SAML_PASSWORD", "WEB_PASSWORD"},
}

// Does not have a Destination, set in the App's Before attribute for both SAML and OIDC
// remove the old --saml-provider flag, but keep the env var for compatibility.
var providerFlag = &cli.StringFlag{
	Name:    "provider",
	Aliases: []string{"R"},
	Usage:   "name of the SAML or Web Identity (OIDC) provider to use",
	EnvVars: []string{"RUNAS_PROVIDER", "SAML_PROVIDER", "WEB_PROVIDER"},
}

/*
 * Other flags - ways to manipulate credential behavior (used with single-flight/non-metadata service commands).
 */
var fmtFlag = &cli.StringFlag{
	Name:        "output",
	Aliases:     []string{"O"},
	Usage:       "credential output format, valid values: env or json",
	EnvVars:     []string{"RUNAS_OUTPUT_FORMAT"},
	Value:       "env",
	Destination: nil,
}

var envFlag = &cli.BoolFlag{
	Name:        "env",
	Aliases:     []string{"E"},
	Usage:       "pass credentials to program as environment variables",
	EnvVars:     []string{"RUNAS_ENV_CREDENTIALS"},
	Destination: nil,
}

var sessionFlag = &cli.BoolFlag{
	Name:        "session",
	Aliases:     []string{"s"},
	Usage:       "use session token credentials instead of role credentials",
	EnvVars:     []string{"RUNAS_SESSION_CREDENTIALS"},
	Destination: nil,
}

var refreshFlag = &cli.BoolFlag{
	Name:        "refresh",
	Aliases:     []string{"r"},
	Usage:       "force a refresh of the cached credentials",
	Destination: nil,
}

var expFlag = &cli.BoolFlag{
	Name:        "expiration",
	Aliases:     []string{"e"},
	Usage:       "show credential expiration time",
	Destination: nil,
}

var whoamiFlag = &cli.BoolFlag{
	Name:        "whoami",
	Aliases:     []string{"w"},
	Usage:       "print the AWS identity information for the provided profile credentials",
	Destination: nil,
}
