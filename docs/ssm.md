---
title: SSM Session Support
---

aws-runas provides built-in support for accessing EC2 instances via SSM sessions.  If the built-in code is insufficient,
or there is a new SSM feature which aws-runas doesn't support, there is an option to utilize the external AWS SSM session
plugin.

### Prerequisites

First, and probably most obvious, is that the EC2 instance must have the SSM agent installed and properly registered
with the SSM service.  Shell access to the instance should be supported by any agent version.  Port forwarding and SSH
support require at least agent version 2.3.672.0 installed on the instance.

If you plan on using the AWS-provided SSM session plugin (versus the built-in client), you will need version 1.1.26.0, or
higher, installed on your local system.  Instructions for installing the AWS helper plugin can be found
[here](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)

It is _not_ required that you also install the AWS CLI tools as instructed in the directions, but they are useful tools
for interacting with AWS outside the web console.

### EC2 Target Resolution

The SSM session API requires that you know the EC2 instance ID in order to establish a session with it.  You are free to
use instance IDs, but aws-runas also allows other, friendlier, methods to resolve additional instance attributes to an
instance ID.  If the target argument does not look like an EC2 instance ID, the following methods will be used in an
attempt to find the desired instance ID:

  * By tag, in the form of `tag_name:tag_value`
  * By public or private IP address (or a resolvable DNS A (or AAAA) record for the instance)
  * By DNS TXT record which returns the instance ID

(Note, if the supplied argument matches multiple EC2 instances, the 1st value found is used. Since the AWS APIs could
return data in any order, you should not expect those results to remain consistent over time. Try to use target resolution
names which will only match a single EC2 instance.)

### Shell Access

Use the `ssm shell` subcommand to establish a shell session with the SSM agent on the requested target.

#### Example

```shell
aws-runas ssm shell my-profile i-deadbeef
```

#### Shell subcommand help
```shell
NAME:
   aws-runas ssm shell - Start an SSM shell session

USAGE:
   aws-runas ssm shell [command options] profile_name target_spec

DESCRIPTION:
   Create an SSM shell session with the specified 'target_spec' using configuration from the
   given 'profile_name'.  The target string can be an EC2 instance ID, a tag key:value string
   which uniquely identifies an EC2 instance, the instance's private IPv4 address, or a DNS
   TXT record whose value is EC2 instance ID.

OPTIONS:
   --plugin, -P  Use the SSM session plugin instead of built-in code (default: false)
   --help, -h    show help (default: false)

```

### Port Forwarding

Use the `ssm forward` subcommand to establish a port forwarding session with the SSM agent on the requested target.
This command accepts an optional `-p` argument which will explicitly set the local port for the forwarding session.
If left at the default, a random port on the local machine will be used for the forwarding connection.

#### Example

To forward local port 8888 to port 9000 on the EC2 instance i-deadbeef:
```shell
aws-runas ssm forward -p 8888 my-profile i-deadbeef:9000
```

#### Forward subcommand help
```shell
NAME:
   aws-runas ssm forward - Start an SSM port forwarding session

USAGE:
   aws-runas ssm forward [command options] profile_name target_spec

DESCRIPTION:
   Create an SSM port forwarding session with the specified 'target_spec' using configuration
   from the given 'profile_name'.  The 'target_spec' is a colon-separated value of the target
   and remote port number (ex. i-01234567:8080).  The target string can be an EC2 instance ID,
   a tag key:value string which uniquely identifies an EC2 instance, the instance's private
   IPv4 address, or a DNS TXT record whose value is EC2 instance ID.  If the '-p' option is
   given, the port forwarding session will listen on the specified port on the local system,
   otherwise a random port is used.

OPTIONS:
   --port value, -p value  The local port for the forwarded connection (default: random port)
   --plugin, -P            Use the SSM session plugin instead of built-in code (default: false)
   --help, -h              show help (default: false)
```

### SSH Access

Use the `ssm ssh` subcommand to establish an SSH session with the SSM agent on the requested target.
This subcommand is not intended to be invoked directly. Refer to the
[AWS Documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-getting-started-enable-ssh-connections.html)
for instructions on setting up the local and remote system to allow SSH connectivity over SSM.

#### Example

This is a sample ssh config file entry to enable SSH connectivity to an SSM connected instance.  The elements on the
`Host` line can be modified to capture how you will be access the host, this example uses the EC2 instance ID.  For the
`ProxyCommand`, the `my_profile` element can be omitted if you will supply the profile name another way (likely via the
AWS_PROFILE environment variable).

```text
Host i-* mi-*
    ProxyCommand sh -c "aws-runas ssm ssh my_profile %h:%p"

```

#### SSH subcommand help
```shell
NAME:
   aws-runas ssm ssh - Start an SSH over SSM session

USAGE:
   aws-runas ssm ssh [command options] profile_name target_spec

DESCRIPTION:
   Create an SSH over SSM session with the specified 'target_spec' using configuration from
   the given 'profile_name'.  The 'target_spec' is a colon-separated value of the target and an
   optional remote port number (ex. i-01234567:2222).  If no port is provided, the well-known
   SSH port is used.  The target string can be an EC2 instance ID, a tag key:value string which
   uniquely identifies an EC2 instance, the instance's private IPv4 address, or a DNS TXT record
   whose value is EC2 instance ID.
   
   This feature is meant to be used in SSH configuration files according to the AWS documentation
   at https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-getting-started-enable-ssh-connections.html
   except that the ProxyCommand syntax changes to:
     ProxyCommand sh -c "aws-runas ssm ssh profile_name %h:%p"
   Where profile_name is the AWS configuration profile to use (you should also be able to use the
   AWS_PROFILE environment variable, in which case the profile_name could be omitted), and %h:%p
   are standard SSH configuration substitutions for the host and port number to connect with, and
   can be left as-is

OPTIONS:
   --plugin, -P  Use the SSM session plugin instead of built-in code (default: false)
   --help, -h    show help (default: false)
```