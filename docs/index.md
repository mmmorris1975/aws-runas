---
title: Home
---

aws-runas is a command line tool which provides a friendly way to do the AWS STS AssumeRole operation, so you can perform
AWS API actions using a particular set of permissions.  Starting in version 3.0, aws-runas supports all the AWS AssumeRole
methods (IAM, SAML, Web Identity/OIDC), including token/code based multi-factor authentication (MFA) for all methods, and
push MFA for SAML and Web Identity operations.  The tool also features HTTP endpoints which emulate the EC2 and ECS metadata
credential services, as well as the ability to connect to EC2 instances using SSM shell, port forwarding, or SSH sessions
using a built-in SSM client, or the AWS-provided plugin.  All of this can be accomplished with configuration of the canonical
.aws/config file, or supplying configuration data directly on the command line.

Caching is implemented at multiple layers of the application to minimize the need to supply MFA input, or external identity
credentials, until you are required to do so.  The results of the AssumeRole AWS API call are also cached so that the AWS
credentials are available across invocations of aws-runas.  The cached files can be found inside the canonical .aws directory
all with file names starting with `.aws_`.

If using MFA, when the cached credentials approach expiration you will be prompted to complete the MFA process during the
next execution of aws-runas. (Since this is a wrapper program, there's no way to know when credentials need to be refreshed
in the middle of the called program execution) If MFA is not required for the assumed role, the credentials should refresh
without user intervention when aws-runas is next executed.

There are no external libraries, or language or runtime dependencies, necessary to run the program. The compiled
platform-specific executables contain everything necessary so you can simply download the file and do a small bit of setup;
after that, you're off and running.