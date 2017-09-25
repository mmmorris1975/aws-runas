# go-aws-runas

A Go rewrite of the original [aws-runas](https://github.com/mmmorris1975/aws-runas "aws-runas").  Unscientific testing
indicates a 25-30% performance improvement over the python-based version of this tool

It's still a command to provide a friendly way to do an AWS STS AssumeRole operation so you can perform AWS API actions
using a particular set of permissions.  Includes integration with roles requiring MFA authentication!  Works
off of profile names configured in the AWS SDK configuration file.

This tool initially performs an AWS STS GetSessionToken call to handle MFA credentials, caches the session credentials,
then makes the AssumeRole call.  This allows us to not have to re-enter the MFA information (if required) every time
AssumeRole is called (or when the AssumeRole credentials expire), only when new Session Tokens are requested
(by default 12 hours).  These credentials are not compatible with credentials cached by awscli, however they should be
compatible with versions of this tool build in different languages.

If using MFA, when the credentials approach expiration you will be prompted to re-enter the MFA token value to refresh
the credentials during the next execution of aws-runas. (Since this is a wrapper program, there's no way to know when
credentials need to be refreshed in the middle of the called program execution) If MFA is not required for the assumed
role, the credentials should refresh without user intervention when aws-runas is next executed.

Since it's written in Go, there is no runtime dependency on external libraries, or language runtimes, just take the
compiled executable and "go".  Like the original aws-runas, this program will cache the credentials returned for the
assumed role.

See the following for more information on AWS SDK configuration files:

- http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html
- https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration
- https://boto3.readthedocs.io/en/latest/guide/configuration.html#aws-config-file

## Build Requirements

Developed and tested using the go 1.9 tool chain, aws-sdk-go v1.10.50, and kingpin.v2 v2.2.5
*NOTE* This project uses the (currently) experimental `dep` dependency manager.  See https://github.com/golang/dep for details.

## Building and Installing

Assuming you have a go workspace, and GOPATH environment variable set (https://golang.org/doc/code.html#Organization):
  1. Run `go get -d github.com/mmmorris1975/go-aws-runas`
  2. Run `dep ensure` to check/retrieve dependencies
  3. Then run `go build -o aws-runas github.com/mmmorris1975/go-aws-runas` to create the executable `aws-runas` in the current directory

## Configuration

To configure a profile in the .aws/config file for using AssumeRole, make sure the `source_profile` and `role_arn` attributes are
set for the profile.  The `role_arn` attribute will determine which role will be assumed for that profile.  The `source_profile`
attribute specifies the name of the profile which will be used to perform the GetSessionToken operation.

If the `mfa_serial` attribute is present in the profile configuration, That MFA device will be used when requesting or refreshing
the session token.

Example:

    [profile admin]
    source_profile = default
    role_arn = arn:aws:iam::987654321098:role/admin_role
    mfa_serial = arn:aws:iam::123456789098:mfa/iam_user

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
  * GetGroupPolicies
  * ListGroupPolicies
  * GetPolicy
  * GetPolicyVersion

## Usage
    usage: go-aws-runas [<flags>] [<profile>] [<cmd>...]

    Create an environment for interacting with the AWS API using an assumed role

    Flags:
      -h, --help              Show context-sensitive help (also try --help-long and --help-man).
      -d, --duration=12h0m0s  duration of the retrieved session token
      -l, --list-roles        list role ARNs you are able to assume
      -m, --list-mfa          list the ARN of the MFA device associated with your account
      -e, --expiration        Show token expiration time
      -s, --session           print eval()-able session token info, or run command using session token credentials
      -r, --refresh           force a refresh of the cached credentials
      -v, --verbose           print verbose/debug messages
      -V, --version           Show application version.

    Args:
      [<profile>]  name of profile
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

## Contributing

The usual github model for forking the repo and creating a pull request is the preferred way to
contribute to this tool.  Bug fixes, enhancements, doc updates, translations are always welcomed.
