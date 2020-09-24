# aws-runas

[![CircleCI](https://circleci.com/gh/mmmorris1975/aws-runas.svg?style=shield&circle-token=3b49323c5e6109720c3cf1d581b26cd36eb598ca)](https://circleci.com/gh/mmmorris1975/aws-runas)
[![Go Report Card](https://goreportcard.com/badge/github.com/mmmorris1975/aws-runas)](https://goreportcard.com/report/github.com/mmmorris1975/aws-runas)

A friendly way to do AWS STS AssumeRole operations so you can perform AWS API actions using a particular set of permissions.
Includes support for IAM user credentials and SAML SSO, including MFA for both!  Works off of profile names configured
in the AWS SDK configuration file.

The tool will cache the credentials retrieved from AWS in order to minimize API calls to AWS, as well as minimize the entry
of MFA codes (for roles requiring MFA).

Full documentation for downloading, configuring and running aws-runas can be found [here](https://mmmorris1975.github.io/aws-runas/)

Since it's written in Go, there is no runtime dependency on external libraries, or language runtimes, just download the
compiled executable and "go".

## Installing

Pre-compiled binaries for various platforms can be downloaded [here](https://github.com/mmmorris1975/aws-runas/releases/latest)

## Usage
    usage: aws-runas [<flags>] <command> [<args> ...]
    
    Create an environment for interacting with the AWS API using an assumed role
    
    Flags:
      -h, --help                     Show context-sensitive help (also try --help-long and --help-man).
          --ec2                      Run a mock EC2 metadata service to provide role credentials
          --ecs                      Run a mock ECS credential endpoint to provide role credentials
      -v, --verbose                  Print verbose/debug messages
      -E, --env                      Pass credentials to program as environment variables
      -e, --expiration               Show credential expiration time
      -O, --output=env               Credential output format, valid values: env (default) or json
      -w, --whoami                   Print the AWS identity information for the provided profile
      -u, --update                   Check for updates to aws-runas
      -D, --diagnose                 Run diagnostics to gather info to troubleshoot issues
      -l, --list-roles               List role ARNs you are able to assume
      -m, --list-mfa                 List the ARN of the MFA device associated with your IAM account
      -r, --refresh                  Force a refresh of the cached credentials
      -s, --session                  Print eval()-able session token info, or run command using session token credentials
      -d, --duration=DURATION        Duration of the retrieved session token
      -a, --role-duration=ROLE-DURATION  
                                     Duration of the assume role credentials
      -o, --otp=OTP                  MFA token code
      -M, --mfa-serial=MFA-SERIAL    Serial number (or AWS ARN) of MFA device needed to perform Assume Role operation
      -X, --external-id=EXTERNAL-ID  External ID to use to Assume the Role
      -J, --jump-role=JUMP-ROLE      ARN of the 'jump role' to use with SAML integration
      -S, --saml-url=SAML-URL        URL of the SAML authentication endpoint
      -U, --saml-user=SAML-USER      Username for SAML authentication
      -P, --saml-password=SAML-PASSWORD  
                                     Password for SAML authentication
      -R, --saml-provider=SAML-PROVIDER  
                                     The name of the saml provider to use, and bypass auto-detection
      -V, --version                  Show application version.
    
    Commands:
      help [<command>...]
        Show help.
    
      shell [<profile>] [<target>]
        Start an SSM shell session to the given target
    
      forward [<flags>] [<profile>] [<target>]
        Start an SSM port-forwarding session to the given target
    
      password [<profile>]
        Set the SAML password for the specified profile

## Building

### Build Requirements

Developed and tested using the go 1.13 tool chain and aws-sdk-go v1.28.12  
*NOTE* This project uses [go modules](https://github.com/golang/go/wiki/Modules) for dependency management

### Build Steps

A Makefile is included with the source code, and executing the default target via the `make` command should install all dependent
libraries and make the executable for your platform (or platform of choice if the GOOS and GOARCH env vars are set)

## Contributing

The usual github model for forking the repo and creating a pull request is the preferred way to
contribute to this tool.  Bug fixes, enhancements, doc updates, translations are always welcomed.

The documentation at the [doc site](https://mmmorris1975.github.io/aws-runas/) all lives under the docs directory in
this repository. It uses [Markdown](https://guides.github.com/features/mastering-markdown/) for the documentation format.
Everyone is welcome to submit pull requests with documentation updates to help correct or clarify the documentation for
this tool.
