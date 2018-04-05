# aws-runas

[![CircleCI](https://circleci.com/gh/mmmorris1975/aws-runas.svg?style=svg)](https://circleci.com/gh/mmmorris1975/aws-runas)
[![Go Report Card](https://goreportcard.com/badge/github.com/mmmorris1975/aws-runas)](https://goreportcard.com/report/github.com/mmmorris1975/aws-runas)

A Go rewrite of the original [aws-runas](https://github.com/mmmorris1975/py-aws-runas "aws-runas").  Unscientific testing
indicates a 25-30% performance improvement over the python-based version of this tool

It's still a command to provide a friendly way to do an AWS STS AssumeRole operation so you can perform AWS API actions
using a particular set of permissions.  Includes integration with roles requiring MFA authentication!  Works
off of profile names configured in the AWS SDK configuration file.

AWS supports AssumeRole credentials which can be valid for up to 12 hours.  aws-runas supports specifying this duration
via command-line options, environment variables, and custom configuration file attributes (see below).  The received credentials
are cached on the local system and will be used until expiration.  To keep backwards compatibility with the behavior
of previous aws-runas versions, requests for AssumeRole credentials of 1 hour (the default) or less, and using MFA, will
first call GetSessionToken() to get a longer-lived set of session token credentials (12 hours, by default) which can carry
the MFA activity for longer than 1 hour.  This alleviates the need to re-MFA every hour (or less) as the AssumeRole
credentials expire, as the call to get new AssumeRole credentials will be made using the session token credentials instead
of the (probably static) credentials, which would require input of a new MFA token code.

The credentials obtained from either the AssumeRole or GetSessionToken operations will be cached on the local system in
the same directory where the SDK configuration file lives (by default $HOME/.aws/).  This allows a set of temporary
credentials to be used multiple times, and carry along the status of any required MFA activities, until the credentials
expire.  Credentials cached for the AssumeRole operation will be in a file specific to the role the credentials were
requested for.  Session token credentials will be cached in a file specific to the profile used to call the
GetSessionToken operation.  This is either the profile specified by the `source_profile` configuration, for a profile
which uses roles, or the name of the profile directly (if profile not using roles).  This allows the session token
credentials to be re-used across multiple roles configured to use the same source profile configuration.

If using MFA, when the cached credentials approach expiration you will be prompted to re-enter the MFA token value to
refresh the credentials during the next execution of aws-runas. (Since this is a wrapper program, there's no way to know
when credentials need to be refreshed in the middle of the called program execution) If MFA is not required for the
assumed role, the credentials should refresh without user intervention when aws-runas is next executed.

Since it's written in Go, there is no runtime dependency on external libraries, or language runtimes, just take the
compiled executable and "go".  Like the original aws-runas, this program will cache the credentials returned for the
assumed role.

See the following for more information on AWS SDK configuration files:

- http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html
- https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration
- https://boto3.readthedocs.io/en/latest/guide/configuration.html#aws-config-file

## Installing

Pre-compiled binaries for various platforms can be downloaded [here](https://github.com/mmmorris1975/aws-runas/releases/latest)

## Building

### Build Requirements

Developed and tested using the go 1.10 tool chain, aws-sdk-go v1.13.25, and kingpin.v2 v2.2.6
*NOTE* This project uses the (currently) experimental `dep` dependency manager.  See https://github.com/golang/dep for details.

### Build Steps

A Makefile is now included with the source code, and executing the default target via the `make` command should install all dependent
libraries and make the executable for your platform (or platform of choice if the GOOS and GOARCH env vars are set)

## Configuration

To configure a profile in the .aws/config file for using AssumeRole, make sure the `source_profile` and `role_arn` attributes are
set for the desired profile.  The `role_arn` attribute will determine which role to assume for that profile.  The `source_profile`
attribute specifies the name of the profile which will be used to perform the GetSessionToken operation.  If you wish to supply an MFA
code when doing the GetSessionToken call, you **MUST** specify the `mfa_serial` attribute in the profile referenced by `source_profile`

If the `mfa_serial` attribute is present in the profile configuration, That MFA device will be used when requesting or refreshing
the session token.  If the attribute is not found in the profile configuration, the program will attempt to find it in the section
referenced by `source_profile`, in an attempt to simplify the config file.  (NOTE: this is a non-standard configuration, and may break
other tools which require the mfa_serial attribute inside the profile config to make the AssumeRole API call, [ex: awscli])

Example (compatible with awscli `--profile` option):

    [profile admin]
    source_profile = default
    role_arn = arn:aws:iam::987654321098:role/admin_role
    mfa_serial = arn:aws:iam::123456789098:mfa/iam_user

Example (NOT compatible with awscli `--profile` option, if MFA required for AssumeRole):

    [default]
    mfa_serial = arn:aws:iam::123456789098:mfa/iam_user

    [profile admin]
    source_profile = default
    role_arn = arn:aws:iam::987654321098:role/admin_role

### Custom configuration attributes

The program supports custom configuration attributes in the .aws/config file to specify the session token and assume role
credential lifetime.  These are non-standard attributes to the AWS SDK, but should be ignored by the SDK and not cause any
issues.  Values are specified as golang time.Duration strings (https://golang.org/pkg/time/#ParseDuration).  These attributes
are handled the same way as the mfa_serial attribute: they can be specified as part of a profile directly, as part of a
source_profile, or as part of the default profile.

  * `session_token_duration` This attribute specifies the lifetime of the session token credentials (which carry the MFA information)
  * `credentials_duration` This attribute specifies the lifetime of the assume role credentials requested by aws-runas

### Environment variables

Standard AWS SDK environment variables are supported by this program.  (See the `Environment Variables` section in
https://docs.aws.amazon.com/sdk-for-go/api/aws/session/) Most will be passed through to the calling program except
for the `AWS_PROFILE` environment variable which will be explicitly unset before aws-runas calls the program.  (It only
affects the environment variable for the execution of aws-runas, the setting in the original environment is unaffected)

If the `AWS_PROFILE` environment variable is set, it will be used in place of the 'profile' argument to the command.  In
this example, the 'aws s3 ls' command will be executed using the profile 'my_profile'

    $ AWS_PROFILE=my_profile aws-runas aws s3 ls

Additionally, the custom config attributes above are also available as the environment variables `SESSION_TOKEN_DURATION`
and `CREDENTIALS_DURATION`

### Required AWS permissions

The user's credentials used by this program will need access to call the following AWS APIs to function:

  * AssumeRole (to get the credentials for running under an assumed role)
  * GetSessionToken (to get the session token credentials for running a command or calling AssumeRole)
  * ListMFADevices (get MFA devices for `-m` option)

The following API calls are used by the `-l` option to find assume-able roles for the calling user:
  * GetUser
  * ListGroupsForUser
  * GetUserPolicy
  * ListUserPolicies
  * GetGroupPolicy
  * ListGroupPolicies
  * GetPolicy
  * GetPolicyVersion

A generic sample policy can be found [here](https://github.com/mmmorris1975/aws-runas/docs/iam_policy.json). The document
is missing permissions to perform the AssumeRole operation, since that operation is highly-privileged it should be created
as needed outside of this policy.  Also consider removing the '*' character in the account number field of the `Resource`
ARNs, and replace with your specific AWS account number (The Resource: * configuration for the ListMFA permission is
required, do not change that)

## Usage
    usage: aws-runas [<flags>] [<profile>] [<cmd>...]

    Create an environment for interacting with the AWS API using an assumed role

    Flags:
      -h, --help               Show context-sensitive help (also try --help-long and --help-man).
      -d, --duration=DURATION  duration of the retrieved session token
      -a, --role-duration=ROLE-DURATION
                               duration of the assume role credentials
      -l, --list-roles         list role ARNs you are able to assume
      -m, --list-mfa           list the ARN of the MFA device associated with your account
      -e, --expiration         Show token expiration time
      -c, --make-conf          Build an AWS extended switch-role plugin configuration for all available roles
      -s, --session            print eval()-able session token info, or run command using session token credentials
      -r, --refresh            force a refresh of the cached credentials
      -v, --verbose            print verbose/debug messages
      -M, --mfa-arn=MFA-ARN    ARN of MFA device needed to perform Assume Role operation
      -u, --update             Check for updates to aws-runas
      -V, --version            Show application version.

    Args:
      [<profile>]  name of profile, or role ARN
      [<cmd>]      command to execute using configured profile


### Listing available roles

Use the `-l` option to see the list of role ARNs your IAM account is authorized to assume.
May be helpful for setting up your AWS config file.  If `profile` arg is specified, list
roles available for the given profile, or the default profile if not specified.  May be
useful if you have multiple profiles configured each with their own IAM role configurations

### Listing available MFA devices

Use the `-m` option to list the ARNs of any MFA devices associated with your IAM account.
May be helpful for setting up your AWS config file.  If `profile` arg is specified, list
MFA devices available for the given profile, or the default profile if not specified. May
be usefule if you have multiple profiles configured each with their own MFA device

### Displaying session token expiration

Use the `-e` option to display the date and time which the session token will expire. If
`profile` arg is specified, display info for the given profile, otherwise use the 'default'
profile.  Specifying the profile name may be useful if you have multiple profiles configured
which you get session tokens for.

### Injecting SessionToken credentials into the environment

Use the `-s` option to output and eval()-able set of environment variables for the session
token credentials. If `profile` arg is specified, display the session token credentials for
the given profile, otherwise use the `default` profile.

Example:

    $ aws-runas -s
    export AWS_ACCESS_KEY_ID='xxxxxx'
    export AWS_SECRET_ACCESS_KEY='yyyyyy'
    export AWS_SESSION_TOKEN='zzzzz'

Or simply `eval $(aws-runas -s)` to add these env vars to the running environment.  Since
session tokens generally live for multiple hours, injecting these credentials into the
environment may be useful when using tools which can do AssumeRole on their own, and manage/refresh
the relativly short-lived AssumeRole credentials internally.

### Injecting AssumeRole credentials into the environment

Running the program with only a profile name will output an eval()-able set of environment
variables for the assumed role credentials which can be added to the current session.

Example:

    $ aws-runas admin-profile
    export AWS_ACCESS_KEY_ID='xxxxxx'
    export AWS_SECRET_ACCESS_KEY='yyyyyy'
    export AWS_SESSION_TOKEN='zzzzz'

Or simply `eval $(aws-runas admin-profile)` to add these env vars in the current session.
With the addition of caching session token credentials, and the ability to automatically
refresh the credentials, eval-ing this output for assumed role credentials is no longer
necessary for most cases, but will be left as a feature of this tool for the foreseeable future.

### Running command using an assumed role with a profile

Running the program specifying a profile name and command will execute the command using the
profile credentials, automatically performing any configured assumeRole operation, or MFA token
gathering.

Example (run the command `aws s3 ls` using the profile `admin-profile`):

    $ aws-runas admin-profile aws s3 ls
    ... <s3 bucket listing here> ...

### Running command using an assumed role with the default profile

Running the program using the default profile is no different than using a custom profile,
simply use `default` as the profile name.

### Running command using session token credentials

If the called application has a built-in capability to perform the AWS AssumeRole action, which
may allow it automatically refresh the AssumeRole credentials using the session token credentials,
wrapping the command execution using aws-runas should allow any AssumeRole operations to work for
as long as those session token credentials are valid.  To make it happen, it's a simple matter of
running aws-runas using the `-s` option.  You should be able sto specify a profile name in the command
and the necessary `source_profile` will be looked up to retrieve any cached session tokens (or fetch
the session tokens (using MFA), if required)

Example (run the terraform, using native AssumeRole configuraiton in terraform, with session tokens):

    $ aws-runas -s admin-profile terraform plan

### Running command using role arn from the command line

The program supports supplying the 'profile' argument as a role ARN instead of a profile in the config file.  This may
be useful for cases where it's not desirable/feasible to keep a local copy of the config file, and the role ARN is static.

If necessary, the ARN for an MFA token can be provided via the `-M` command line option.

    $ aws-runas [-M mfa serial] arn:aws:iam::1234567890:role/my-role terraform plan

## Contributing

The usual github model for forking the repo and creating a pull request is the preferred way to
contribute to this tool.  Bug fixes, enhancements, doc updates, translations are always welcomed.
