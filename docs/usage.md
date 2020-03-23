---
layout: page
title: Program Usage
---
# Program Usage
How to use aws-runas to perform various functions

#### Program Options
```text
usage: aws-runas [<flags>] <command> [<args> ...]

Create an environment for interacting with the AWS API using an assumed role

Flags:
  -h, --help                     Show context-sensitive help (also try --help-long and --help-man).
      --ec2                      Run a mock EC2 metadata service to provide role credentials
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
```

### Environment Variables
In addition to the ["standard" AWS environment variables](https://docs.aws.amazon.com/sdk-for-go/api/aws/session/#hdr-Environment_Variables), the following environment variables can be used in lieu of
command line arguments, or config file properties, to affect the behavior of aws-runas:

  * RUNAS_VERBOSE (boolean) - Set to any "truth-y" value to enable verbose output, like the `-v` flag
  * RUNAS_ENV_CREDENTIALS (boolean) - Set to any "truth-y" value to use environment variables, instead of the container credential endpoint, like the `-E` flag
  * RUNAS_OUTPUT_FORMAT (env or json) - If set to "json" print the credentials as a json object compatible with the aws credential_process configuration setting, otherwise output environment variable statements, like the `-O` flag
  * RUNAS_SESSION_CREDENTIALS (boolean) - Set to any "truth-y" value to use session token credentials, instead of role credentials, like the `-s` flag
  * SESSION_TOKEN_DURATION ([duration](https://golang.org/pkg/time/#ParseDuration)) - A golang time.Duration string to set the lifetime of the session token credentials (12 hour default), like the `-d` flag
  * CREDENTIALS_DURATION ([duration](https://golang.org/pkg/time/#ParseDuration)) - A golang time.Duration string to set the lifetime of the role credentials (1 hour default), like the `-a` flag
  * MFA_CODE (string) - The MFA token code to use for credentials requiring MFA, like the `-o` flag
  * MFA_SERIAL (string) - The MFA device serial number of the IAM user, like the `-m` flag
  * EXTERNAL_ID (string) - The External ID value to pass in the AssumeRole operation, like the `-X` flag
  * JUMP_ROLE_ARN (string) - The ARN of the role to initially assume using SAML credentials, before assuming the actual role for the operation, like the `-J` flag
  * SAML_AUTH_URL (URL) - The URL of the SAML authentication endpoint to authenticate against, like the `-S` flag
  * SAML_USERNAME (string) - The username of the SAML user to use for authentication, like the `-U` flag
  * SAML_PASSWORD (string) - The password of the SAML user to use for authentication, like the `-P` flag


### Diagnostics
Use the `-D` option to perform some rudimentary sanity checking of the configuration for the given profile, and print
the resolved profile data. Some of the items checked are:

  * Detecting static AWS credentials set as environment variables along with file-based credentials
  * Verifying that the region is set in the config file, or via the `AWS_REGION` environment variable
  * Checking that the profile sets the `source_profile` attribute if the `role_arn` attribute is detected
  * Mis-matched or conflicting AWS credential settings
  * Missing static IAM user credentials
  * Local system time is within the allowed time drift for the AWS API

When contacting the developers for support, it is helpful to provide the diagnostic output in conjunction with the
verbose flag `aws-runas -Dv`

**WARNING** The `-v` output will contain sensitive data, including AWS credentials (temporary STS credentials, not long-lived
user IAM credentials), so be sure to redact sensitive data before sending the output via unsecured channels.


### Listing Available Roles
Use the `-l` option to see the list of role ARNs your IAM account is authorized to assume. May be helpful for setting up
your AWS config file. If `profile` arg is specified, list roles available for the given profile, or the default profile
if not specified. May be useful if you have multiple profiles configured each with their own IAM role configurations.

This option will only return roles which are explicitly specified in the SAML authorizations or IAM policies assigned to
the user, or any groups they belong to.  It will not return roles containing wildcard characters, since that value can
not be explicitly configured in the .aws/config file for the role_arn attribute.


### Listing MFA Device
Use the `-m` option to list the ARNs of any MFA devices associated with your IAM account. May be helpful for setting up
your AWS config file. If `profile` arg is specified, list MFA devices available for the given profile, or the default
profile if not specified. May be useful if you have multiple profiles configured, each with their own MFA device.

This command-line option is not supported for profiles using SAML single-signon.


### Showing Credential Expiration
Use the `-e` option to display the date and time which the cached credentials will expire. If `profile` arg is specified,
display the expiration for the credentials used with the given profile, otherwise use the 'default' profile. Specifying
the profile name may be useful if you have multiple profiles configured, using different source_profile settings.


### Showing Profile Identity Information
Use the `-w` option to display the AWS identity information for the specified profile.  Use this information to troubleshoot
suspected configuration issues to verify that the returned `Account` and `Arn` information lines up with what is configured
for the profile.


### Assuming Roles
The bread and butter of aws-runas, fetching temporary role credentials from AWS so you can use them with other tools.

#### Running a command using a profile
Executing aws-runas specifying a profile name, and a command to run, will retrieve a set of temporary role credentials,
expose those credentials as environment variables, then execute the provided command so that the environment variable
credentials are used as the credentials for making AWS API calls. The following example demonstrates how to run the
`aws s3 ls` command from the awscli tools using the role specified in a profile named `admin-profile`:

```text
$ aws-runas admin-profile aws s3 ls
... <s3 bucket listing here> ...
```

#### Running a command using a role ARN
The program supports supplying the 'profile' argument as a role ARN instead of a named profile in the config file. This
may be useful for cases where it's not desirable/feasible to keep a local copy of the config file, and the role ARN is static.

When using the tool in this way, the necessary IAM credentials must be supplied as either environment variables, or configured
in the `default` section of the ~/.aws/credentials file.

If necessary, the ARN for an MFA token can be provided via the `-M` command line option.

```text
$ aws-runas [-M mfa serial] arn:aws:iam::1234567890:role/my-role terraform plan
```

#### Executing local docker containers using role credentials
Special consideration must be given when executing docker containers which need to access AWS services using role credentials,
and the container process does not handle the role assumption (it expects the role credentials to be provided to it).  Use
the `-E` command line option to instruct aws-runas to pass the credentials as environment variable to docker, like this:

```text
$ aws-runas -E my-profile docker run -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e AWS_REGION ...
```

#### Injecting assume role credentials in the environment
Running the program with only a profile name will output an eval()-able set of environment variables for the assumed role
credentials which can be added to the current session.

Example:

```text
$ aws-runas admin-profile
export AWS_ACCESS_KEY_ID='xxxxxx'
export AWS_SECRET_ACCESS_KEY='yyyyyy'
export AWS_SESSION_TOKEN='zzzzz'
```

Or simply `eval $(aws-runas admin-profile)` to add these env vars in the current session. While this behavior is supported,
it is certainly not the optimal way to use aws-runas, since these credentials have a short lifetime (1 hour, by default),
and will not get automatically refreshed when they expire.

### Session Token Credentials
Session Token credentials are the type of credentials aws-runas retrieves before making the calls to assume a role. The
benefit of this is that Session Token credentials are able to carry the status of any provided MFA code for the lifetime
of the Session Token credentials, which are much longer lived (12 hours, by default) than Assume Role credentials
(1 hour by default). This means that if you need to use MFA when assuming roles, you will only need to re-enter the MFA
codes when the Session Token credentials expire, instead of every time the Assume Role credentials expire.

The aws-runas tool provides the ability to use the Session Token credentials directly, instead of the Assume Role
credentials when interacting with the AWS API. While this is typically not necessary for nearly every use case, there
are some advanced scenarios where this may be required. One such case would be if the tool you're trying to use has the
built-in capability to assume roles, but a long running workflow would get disrupted when those role credentials expire
and would require re-entry of the MFA code to continue.  In this case using aws-runas to inject Session Token credentials
for the tool would mean that the MFA code entry would only have to occur once (or maybe not at all, if it's able to find
a suitable set of cached Session Token credentials)

#### Running a command using session token credentials
To inject the Session Token credentials before running a command, it's simply a matter of adding the `-s` option to the
command.

This example assumes that you have roles configured directly in your terraform AWS provider, but wish to use Session Token
credentials to minimize the possibility of the workflow getting disrupted by expired role credentials:

```text
$ aws-runas -s admin-profile terraform plan
```

#### Executing local docker containers using session token credentials
Special consideration must be given when executing docker containers which need to access AWS services using session token
credentials, typically for cases where the container app manages their own assume role activities.  Use the `-E` command
line option, along with the `-s` option  to instruct aws-runas to pass the credentials as environment variable to docker, like this:

```text
$ aws-runas -Es my-profile docker run -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e AWS_REGION ...
```

#### Injecting session token credentials in the environment
Much like injecting role credentials into your session's environment, aws-runas supports injecting Session Token
credentials in to your environment. It's simply a matter of executing aws-runas using the `-s` flag without specifying
a command, and it will output an eval()-able set of environment variables for the session token credentials. If `profile`
arg is specified, display the session token credentials for the given profile, otherwise use the `default` profile.

Example:

```text
$ aws-runas -s
export AWS_ACCESS_KEY_ID='xxxxxx'
export AWS_SECRET_ACCESS_KEY='yyyyyy'
export AWS_SESSION_TOKEN='zzzzz'
```

Or simply `eval $(aws-runas -s)` to add these env vars in the current session. While this behavior is supported,
it is certainly not the optimal way to use aws-runas, since you lose the ability to track when these credentials will
expire and have aws-runas handle refreshing them.

### Using Multi-factor Authentication (MFA)
For roles or API calls requiring successful MFA, the tool will prompt you to enter the current MFA code if the profile
is configured with the `mfa_serial` attribute, or the authentication path for the SAML identity provider indicates that
performing multi-factor authentication is required. Alternatively, you can supply the MFA token using the `-o` command line
option (requires version 1.3.4 or higher)
