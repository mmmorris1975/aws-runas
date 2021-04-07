---
title: Program Usage
---

How to use aws-runas to perform various functions

#### Program Options
```text
NAME:
   aws-runas - Create an environment for interacting with the AWS API using an assumed role

USAGE:
   aws-runas [global options] [subcommand] profile [arguments...]

VERSION:
   3.0-beta

COMMANDS:
   list, ls              Shows IAM roles or MFA device configuration
   serve, srv            Serve credentials from a listening HTTP service
   ssm                   Helpful shortcuts for working with SSM sessions
   password, passwd, pw  Set or update the stored password for an external identity provider
   diagnose, diag        run diagnostics to gather information to aid in troubleshooting
   help, h               Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --duration value, -d value       duration of the retrieved session token (default: 12 hours)
   --role-duration value, -a value  duration of the assume role credentials (default: 1 hours)
   --otp value, -o value            MFA token code
   --mfa-serial value, -M value     serial number (or AWS ARN) of MFA device needed to assume role
   --mfa-type value, -t value       use specific MFA type instead of provider auto-detection logic
   --external-id value, -X value    external ID to use with Assume Role
   --jump-role value, -J value      ARN of the 'jump role' to use with SAML or Web Identity integration
   --saml-url value, -S value       URL of the SAML authentication endpoint
   --web-url value, -W value        URL of the Web Identity (OIDC) authentication endpoint
   --web-redirect value, -T value   Web Identity (OIDC) redirect URI
   --web-client value, -C value     Web Identity (OIDC) client ID
   --username value, -U value       username for SAML or Web Identity (OIDC) authentication
   --password value, -P value       password for SAML or Web Identity (OIDC) authentication
   --provider value, -R value       name of the SAML or Web Identity (OIDC) provider to use
   --env, -E                        pass credentials to program as environment variables
   --output value, -O value         credential output format, valid values: env or json (default: "env")
   --session, -s                    use session token credentials instead of role credentials
   --refresh, -r                    force a refresh of the cached credentials
   --expiration, -e                 show credential expiration time
   --whoami, -w                     print the AWS identity information for the provided profile credentials
   --list-mfa, -m                   list the ARN of the MFA device associated with your IAM account
   --list-roles, -l                 list role ARNs you are able to assume
   --update, -u                     check for updates to aws-runas
   --diagnose, -D                   run diagnostics to gather information to aid in troubleshooting
   --verbose value, -v value        output debug logging, use twice for AWS call tracing
   --help, -h                       show help
   --version, -V                    print the version

```

### Environment Variables

In addition to the ["standard" AWS environment variables](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/config#EnvConfig),
the following environment variables can be used in lieu of command line arguments, or config file properties, to affect
the behavior of aws-runas:

  * RUNAS_ENV_CREDENTIALS (boolean) - Set to any "truth-y" value to use environment variables, instead of the container credential endpoint, like the `-E` flag
  * RUNAS_OUTPUT_FORMAT (env or json) - If set to "json", print the credentials as a json object compatible with the aws credential_process configuration setting, otherwise output environment variable statements, like the `-O` flag
  * RUNAS_SESSION_CREDENTIALS (boolean) - Set to any "truth-y" value to use session token credentials, instead of role credentials, like the `-s` flag
  * SESSION_TOKEN_DURATION ([duration](https://golang.org/pkg/time/#ParseDuration)) - A golang time.Duration string to set the lifetime of the session token credentials (12 hour default), like the `-d` flag
  * CREDENTIALS_DURATION ([duration](https://golang.org/pkg/time/#ParseDuration)) - A golang time.Duration string to set the lifetime of the role credentials (1 hour default), like the `-a` flag
  * MFA_CODE (string) - The MFA token code to use for credentials requiring MFA, like the `-o` flag
  * MFA_SERIAL (string) - The MFA device serial number of the IAM user, like the `-M` flag
  * EXTERNAL_ID (string) - The External ID value to pass in the AssumeRole operation, like the `-X` flag
  * JUMP_ROLE_ARN (string) - The ARN of the role to initially assume using SAML credentials, before assuming the actual role for the operation, like the `-J` flag
  * SAML_AUTH_URL (URL) - The URL of the SAML authentication endpoint to authenticate against, like the `-S` flag
  * WEB_AUTH_URL (URL) - The URL of the OIDC authentication endpoint to authenticate against, like the `-W` flag
  * WEB_REDIRECT_URI (string) - The OIDC redirect URL configured for the application in the identity provider, like the `-T` flag
  * WEB_CLIENT_ID (string) - the OIDC client ID configured for the application in the identity provider, like the `-C` flag
  * RUNAS_USERNAME (string) - The username of the SAML or OIDC user to use for authentication, like the `-U` flag.
    The environment variables SAML_USERNAME or WEB_USERNAME are also accepted.
  * RUNAS_PASSWORD (string) - The password of the SAML or OIDC user to use for authentication, like the `-P` flag.
    The environment variables SAML_PASSWORD or WEB_PASSWORD are also accepted.
  * RUNAS_PROVIDER (string) - The name of the SAML or OIDC identity provider to use, overriding auto-detection, like the `-R` flag
    The environment variables SAML_PROFILE or WEB_PROVIDER are also accepted.

### Diagnostics

Use the `diagnose` subcommand, or `-D` option, to perform some rudimentary sanity checking of the configuration for the
given profile, and print the resolved profile data. Some items checked are:

* Detecting static AWS credentials set as environment variables along with file-based credentials
* Verifying that the region is set in the config file, or via the `AWS_REGION` environment variable
* Checking that the profile sets the `source_profile` attribute if the `role_arn` attribute is detected
* Mis-matched or conflicting AWS credential settings
* Missing static IAM user credentials
* Local system time is within the allowed time drift for the AWS API

When contacting the developers for support, it is helpful to provide the diagnostic output in conjunction with the
verbose flag `aws-runas -Dv`

**WARNING** The `-v` output may contain sensitive data, including AWS credentials, so be sure to redact sensitive data
prior to sending the output via unsecured channels.

### Listing Roles

Use the `list roles` subcommand to see the role ARNs your user is authorized to assume. May be helpful for setting up
your AWS config file.  The `-l` command line flag is also available as a shortcut, instead of the full subcommand.

This option will only return roles which are explicitly specified in the SAML authorizations or IAM policies assigned to
the user, or any groups they belong to.  It will not return roles containing wildcard characters, since that value can
not be explicitly configured in the .aws/config file for the role_arn attribute.

Role information is not available when using profiles configured for Web Identity (OIDC), and will result in an error.

### Listing MFA Devices

For profiles associated with IAM users, the `list mfa` subcommand can be used to display the ARN of the MFA device
associated with the user.  The value displayed is suitable for use in the `mfa_serial` configuration attribute in the
.aws/config file.  The `-m` command-line flag can be used as a shortcut, instead of the full subcommand.

Retrieving MFA device details for profiles configured for SAML or Web Identity integration is not supported.

### Show Credential Expiration

Use the `-e` option to display the date and time which the cached credentials will expire for the provided profile.  The
expiration time displayed is only for the STS credentials retrieved from AWS.  Expiration of credentials or sessions
associated with the identity provider used for SAML or OIDC integration are not known, and are not displayed.

### Show Identity Information

Use the `--whoami` command line flag to have aws-runas output the identity associated with the credentials retrieved
for the profile. This output is useful for verifying that the expected role in the correct AWS account is being used. 
For example, if I have a profile called `my-profile`, which is granted access to `MyRole` in AWS account `0123456789`,
you would see output similar to this:

```shell
$ aws-runas --whoami my-profile
{UserId:AROAxxx:my_iam_user Arn:arn:aws:sts::0123456789:assumed-role/MyRole/my_iam_user Account:0123456789}
...
```