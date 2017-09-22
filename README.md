# go-aws-runas

A Go rewrite of the original [aws-runas](https://github.com/mmmorris1975/aws-runas "aws-runas").  Unscientific testing
indicates a 25-30% performance improvement over the python-based version of this tool

It's still a command to provide a friendly way to do an AWS STS assumeRole operation so you can perform AWS API actions
using a particular set of permissions.  Includes integration with roles requiring MFA authentication!  Works
off of profile names configured in the AWS SDK configuration file.

Since it's written in Go, there is no runtime dependency on external libraries, or language runtimes, just take the
compiled executable and "go".  Like the original aws-runas, this program will cache the credentials returned for the
assumed role.  However, unlike the original python program, the cached credentials for this Go program are not compatible
with the awscli.  Another difference from the python version of this tool, you are also able to specify the duration of
the assumed role credentials (but in all honesty, who is going to move from the default/maximum value of 1 hour?)

If using MFA, when the credentials approach expiration you will be prompted to re-enter the MFA token value to refresh
the credentials during the next execution of aws-runas. (Since this is a wrapper program, there's no way to know when
credentials need to be refreshed in the middle of the called program execution) If MFA is not required for the assumed
role, the credentials should refresh without user intervention when aws-runas is executed.

See the following for more information on AWS SDK configuration files:

- http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html
- https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration
- https://boto3.readthedocs.io/en/latest/guide/configuration.html#aws-config-file

## Build Requirements

Developed and tested using the go 1.9 tool chain, aws-sdk-go v1.10.50, and kingpin.v2 v2.2.5

## Building and Installing

_NOTE_ This project uses the (currently) experimental `dep` dependency manager.  See https://github.com/golang/dep for details.
Assuming you have a go workspace, and GOPATH environment variable set (https://golang.org/doc/code.html#Organization):
  1. Run `go get -d github.com/mmmorris1975/go-aws-runas`
  2. Run `dep ensure` to check/retrieve dependencies
  3. Then run `go build -o aws-runas github.com/mmmorris1975/go-aws-runas` to create the executable `aws-runas` in the current directory

## Usage
    usage: aws-runas [<flags>] [<profile>] [<cmd>...]

    Create an environment for interacting with the AWS API using an assumed role

    Flags:
      -h, --help             Show context-sensitive help (also try --help-long and --help-man).
      -d, --duration=1h0m0s  duration of the retrieved session token
      -l, --list-roles       list role ARNs you are able to assume
      -m, --list-mfa         list the ARN of the MFA device associated with your account
      -v, --verbose          print verbose/debug messages
      -V, --version          Show application version.

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

### Generating credentials

Running the program with only a profile name will output an eval()-able set of
environment variable which can be added to the current session.

Example:

    $ aws-runas admin-profile
    export AWS_ACCESS_KEY_ID='xxxxxx'
    export AWS_SECRET_ACCESS_KEY='yyyyyy'
    export AWS_SESSION_TOKEN='zzzzz'

Or simply `eval $(aws-runas admin-profile)` to add these env vars in the current session.
With the addition of caching credentials for the lifetime of the session token, and the
ability to automatically refresh the credentials, eval-ing the output of this utility is
no longer necessary for most cases, but will be left as a feature of this tool for the
foreseeable future.

### Running command using a profile

Running the program specifying a profile name and command will execute the command using the
profile credentials, automatically performing any configured assumeRole operation, or MFA token
gathering.

Example (run the command `aws s3 ls` using the profile `admin-profile`):

    $ aws-runas admin-profile aws s3 ls
    ... <s3 bucket listing here> ...

### Running command using the default profile

Running the program using the default profile is no different than using a custom profile,
simply use `default` as the profile name.

## Contributing

The usual github model for forking the repo and creating a pull request is the preferred way to
contribute to this tool.  Bug fixes, enhancements, doc updates, translations are always welcomed.
