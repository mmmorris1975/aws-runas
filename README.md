# aws-runas

[![CircleCI](https://circleci.com/gh/mmmorris1975/aws-runas.svg?style=shield&circle-token=3b49323c5e6109720c3cf1d581b26cd36eb598ca)](https://circleci.com/gh/mmmorris1975/aws-runas)
[![Go Report Card](https://goreportcard.com/badge/github.com/mmmorris1975/aws-runas)](https://goreportcard.com/report/github.com/mmmorris1975/aws-runas)

A friendly way to do AWS STS AssumeRole operations so you can perform AWS API actions using a particular set of permissions.
Includes integration with roles requiring MFA authentication!  Works off of profile names configured in the AWS SDK configuration file.

The tool will cache the credentials retrieved from AWS in order to minimize API calls to AWS, as well as minimize the entry
of MFA codes (for roles requiring MFA).

Full documentation for downloading, configuring and running aws-runas can be found [here](https://mmmorris1975.github.io/aws-runas/)

Since it's written in Go, there is no runtime dependency on external libraries, or language runtimes, just download the
compiled executable and "go".


## Installing

Pre-compiled binaries for various platforms can be downloaded [here](https://github.com/mmmorris1975/aws-runas/releases/latest)

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
      -D, --diagnose           Run diagnostics to gather info to troubleshoot issues
          --ec2                Run as mock EC2 metadata service to provide role credentials
      -E, --env                Pass credentials to program as environment variables
      -V, --version            Show application version.
    
    Args:
      [<profile>]  name of profile, or role ARN
      [<cmd>]      command to execute using configured profile

## Building

### Build Requirements

Developed and tested using the go 1.12 tool chain and aws-sdk-go v1.18.6  
*NOTE* This project uses [go modules](https://github.com/golang/go/wiki/Modules) for dependency management

### Build Steps

A Makefile is included with the source code, and executing the default target via the `make` command should install all dependent
libraries and make the executable for your platform (or platform of choice if the GOOS and GOARCH env vars are set)

## Contributing

The usual github model for forking the repo and creating a pull request is the preferred way to
contribute to this tool.  Bug fixes, enhancements, doc updates, translations are always welcomed.
