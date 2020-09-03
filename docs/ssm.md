---
layout: page
title: SSM Session Support
---
# SSM Session Support
Starting with version 1.5, the tool supports integration with the SSM Session Manager service, so you are able to open
a shell, or port-forwarding, session with appropriately configured EC2 instances.

Starting with version 2.2, the tool supports the ability to specify the target instance as an EC2 instance identifier,
or using a DNS TXT record which contains the instance ID.

### Prerequisites
In addition to having a target EC2 instance registered with an SSM agent version supporting the desired functionality,
`aws-runas` requires that you install the `session-manager-plugin` helper to handle the communication with the SSM service.
(AWS doesn't publish the messaging specification for this service, so we have to rely on this external tool to enable
this functionality)

The ability to open a shell should be supported by any version of the SSM Agent running on the EC2 instance, however
the port forwarding functionality requires version 2.3.672.0 or higher of the SSM Agent on the instance, and version
1.1.26.0 or higher of the session-manager-plugin installed on your local system.  Instructions for installing the helper
plugin can be found
[here](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)

It is _not_ required that you also install the AWS CLI tools as instructed in the directions, but they are useful tools for
interacting with AWS outside of their web console.

### Shell Access
Using the `shell` subcommand for aws-runas will cause the program to establish a shell session with the SSM agent on the
requested target.

#### Shell Example
`aws-runas shell my-profile i-deadbeef`

#### Command help docs
```text
usage: aws-runas [<flags>] shell [<profile>] [<target>]

Start an SSM shell session to the given target

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
  -o, --otp=OTP            MFA token code
  -u, --update             Check for updates to aws-runas
  -D, --diagnose           Run diagnostics to gather info to troubleshoot issues
      --ec2                Run as mock EC2 metadata service to provide role credentials
  -E, --env                Pass credentials to program as environment variables
  -V, --version            Show application version.

Args:
  [<profile>]  name of profile, or role ARN
  [<target>]   The EC2 instance to connect via SSM
```

### Port Forwarding
Using the `forward` subcommand for aws-runas will cause the program to establish a port-forwarding session with the SSM
agent on the requested target. This command accepts an optional `-p` argument which will explicitly set the local port for
the forwarding session.  If left at the default, a random port on the local machine will be used for the forwarding connection.

#### Forwarding Example
To forward local port 8888 to port 9000 on the EC2 instance i-deadbeef:  
`aws-runas forward -p 8888 my-profile i-deadbeef:9000`

#### Command help docs
```text
usage: aws-runas [<flags>] forward [-p] [<profile>] [<target>]

Start an SSM port-forwarding session to the given target

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
  -o, --otp=OTP            MFA token code
  -u, --update             Check for updates to aws-runas
  -D, --diagnose           Run diagnostics to gather info to troubleshoot issues
      --ec2                Run as mock EC2 metadata service to provide role credentials
  -E, --env                Pass credentials to program as environment variables
  -V, --version            Show application version.
  -p, --port=0             The local port for the forwarded connection

Args:
  [<profile>]  name of profile, or role ARN
  [<target>]   The EC2 instance id and remote port, separated by ':'
```