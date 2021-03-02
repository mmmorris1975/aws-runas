# aws-runas

[![CircleCI](https://circleci.com/gh/mmmorris1975/aws-runas.svg?style=shield&circle-token=3b49323c5e6109720c3cf1d581b26cd36eb598ca)](https://circleci.com/gh/mmmorris1975/aws-runas)
[![Go Report Card](https://goreportcard.com/badge/github.com/mmmorris1975/aws-runas)](https://goreportcard.com/report/github.com/mmmorris1975/aws-runas)

A friendly way to do AWS STS AssumeRole operations so you can perform AWS API actions using a particular set of permissions.
Includes support for IAM user credentials and SAML SSO, including MFA for both!  Works off of profile names configured
in the AWS SDK configuration file.

The tool will cache the credentials retrieved from AWS in order to minimize API calls to AWS, as well as minimize the entry
of MFA codes (for roles requiring MFA).

Version 3.0 is a ground-up rewrite of the tool with a number of behind the scenes updates, and quite a few new features
to make interacting with AWS role credentials easier
  * Added support for Web Identity credentials in addition to SAML credentials
  * The ECS metadata credential service is now feature-comparable to the EC2 metadata credential service
  * The ECS metadata credential service allows dynamic profile credential fetching when a profile name gets appended
    to the service endpoint URL path
  * The EC2 metadata credential service supports using a custom port, which permits the service to run without
    root/admin privileges. Running using the "traditional" 169.254.169.254 address is still supported, but will always
    require elevated privileges for configuring the IP address on a network interface, and running on a privileged port.
  * The EC2 metadata credential service now supports the IMDSv2 token path, and still handles IMDSv1
  * Use a baked-in SSM session client to remove the requirement to install the AWS ssm session plugin, a CLI option
    is provided if use of the plugin is necessary or desired.
  * Add support for SSH over SSM sessions in the build-in client, and via the plugin
  * More coherent and expansive use of subcommands in the CLI to make separation of the various functions in the tool
    clearer. (See Usage section below)
  * Integration/functional tests now include testing SAML and Web Identity functionality with external public IdPs
    (currently Okta and Onelogin)

Version 3.0 TODO list (in no particular order)
  * Documentation
  * Enhancements and fixes from collected feedback
  * Possibly add support for other SAML and OIDC identity provider
  * Consider adding an ECR credential retrieval shortcut

Since it's written in Go, there is no runtime dependency on external libraries, or language runtimes, just download the
compiled executable and "go".

## Installing

Pre-compiled binaries for various platforms can be downloaded [here](https://github.com/mmmorris1975/aws-runas/releases/latest)

## Usage
    NAME:
    aws-runas-v3 - Create an environment for interacting with the AWS API using an assumed role
    
    USAGE:
    aws-runas-v3 [global options] [subcommand] profile [arguments...]
    
    VERSION:
    3.0-alpha
    
    COMMANDS:
    list, ls              Shows IAM roles or MFA device configuration
    serve, srv            Serve credentials from a listening HTTP service
    ssm                   Helpful shortcuts for working with SSM sessions
    password, passwd, pw  Set or update the stored password for an external identity provider
    diagnose, diag        run diagnostics to gather information to aid in troubleshooting
    help, h               Shows a list of commands or help for one command
    
    GLOBAL OPTIONS:
    --duration value, -d value       duration of the retrieved session token (default: 12 hours) [$SESSION_TOKEN_DURATION]
    --role-duration value, -a value  duration of the assume role credentials (default: 1 hours) [$CREDENTIALS_DURATION]
    --otp value, -o value            MFA token code [$MFA_CODE]
    --mfa-serial value, -M value     serial number (or AWS ARN) of MFA device needed to perform Assume Role operation [$MFA_SERIAL]
    --external-id value, -X value    external ID to use with Assume Role [$EXTERNAL_ID]
    --jump-role value, -J value      ARN of the 'jump role' to use with SAML or Web Identity integration [$JUMP_ROLE_ARN]
    --saml-url value, -S value       URL of the SAML authentication endpoint [$SAML_AUTH_URL]
    --web-url value, -W value        URL of the Web Identity (OIDC) authentication endpoint [$WEB_AUTH_URL]
    --web-redirect value, -T value   Web Identity (OIDC) redirect URI [$WEB_REDIRECT_URI]
    --web-client value, -C value     Web Identity (OIDC) client ID [$WEB_CLIENT_ID]
    --username value, -U value       username for SAML or Web Identity (OIDC) authentication [$RUNAS_USERNAME, $SAML_USERNAME, $WEB_USERNAME]
    --password value, -P value       password for SAML or Web Identity (OIDC) authentication [$RUNAS_PASSWORD, $SAML_PASSWORD, $WEB_PASSWORD]
    --provider value, -R value       name of the SAML or Web Identity (OIDC) provider to use [$RUNAS_PROVIDER, $SAML_PROVIDER, $WEB_PROVIDER]
    --env, -E                        pass credentials to program as environment variables (default: false) [$RUNAS_ENV_CREDENTIALS]
    --output value, -O value         credential output format, valid values: env or json (default: "env") [$RUNAS_OUTPUT_FORMAT]
    --session, -s                    use session token credentials instead of role credentials (default: false) [$RUNAS_SESSION_CREDENTIALS]
    --refresh, -r                    force a refresh of the cached credentials (default: false)
    --expiration, -e                 show credential expiration time (default: false)
    --whoami, -w                     print the AWS identity information for the provided profile credentials (default: false)
    --list-mfa, -m                   list the ARN of the MFA device associated with your IAM account (default: false)
    --list-roles, -l                 list role ARNs you are able to assume (default: false)
    --update, -u                     check for updates to aws-runas-v3 (default: false)
    --diagnose, -D                   run diagnostics to gather information to aid in troubleshooting (default: false)
    --verbose value, -v value        output debug logging, use twice for AWS call tracing (default: standard logging)
    --help, -h                       show help (default: false)
    --version, -V                    print the version (default: false)

## Building

### Build Requirements

Developed and tested using the go 1.16 tool chain and aws-sdk-go v1.36.31  
*NOTE* This project uses [go modules](https://github.com/golang/go/wiki/Modules) for dependency management

### Build Steps

A Makefile is included with the source code, and executing the default target via the `make` command should install all dependent
libraries and make the executable for your platform (or platform of choice if the GOOS and GOARCH env vars are set).

Other common make targets which may be useful for local development:
  - clean - to clean up build artifacts
  - linux, darwin, windows - compile program specifically targeting these platforms. Compiled program will be placed
    in the `build` subdirectory of the source tree. Specific architecture can be compiled by setting the GOOS environment variable.
  - zip - create a zip file of the compiled program (compiling it, if necessary). By default, it will compile for the
    platform the command is run on.  Zip file will be placed in the `pkg` subdirectory of the source tree.  Use the
    GOOS and GOARCH environment variables to compile and package for other systems.

## Contributing

The usual github model for forking the repo and creating a pull request is the preferred way to
contribute to this tool.  Bug fixes, enhancements, doc updates, translations are always welcomed.

The documentation at the [doc site](https://mmmorris1975.github.io/aws-runas/) all lives under the docs directory in
this repository. It uses [Markdown](https://guides.github.com/features/mastering-markdown/) for the documentation format.
Everyone is welcome to submit pull requests with documentation updates to help correct or clarify the documentation for
this tool.
