---
layout: page
title: Home
---
# aws-runas Documentation

aws-runas is a command line tool which provides a friendly way to do the AWS STS AssumeRole operation so you can perform
AWS API actions using a particular set of permissions. Includes integration with roles requiring multi-factor authentication
(MFA) and SAML single sign-on! Works with profile names configured in the AWS SDK configuration file, or can use a role
ARN value directly.

Using the default credential lifetime values, aws-runas will call the GetSessionToken API to retrieve a set of
temporary credentials. If the profile specified on the command line is configured to use MFA, then the user will be
prompted to enter the MFA code before making the call to GetSessionToken. This way, the status of the MFA activity is
stored with the credentials returned by the GetSessionToken call, which have a longer lifetime than the role credentials
returned by the AssumeRole API call.  This means that it will minimize the number of times you are required to input your
MFA code when operating in AWS.

The credentials obtained from either the AssumeRole or GetSessionToken operations will be cached on the local system in
the same directory where the SDK configuration files live (by default $HOME/.aws/). This allows a set of temporary
credentials to be used multiple times, and hold the status of any required MFA activities, until the credentials
expire. Credentials cached for the AssumeRole operation will be in a file specific to the role the credentials were
requested for. Session token credentials will be cached in a file specific to the profile used to call the
GetSessionToken operation. This is either the profile set in the source_profile configuration, for a profile which uses
roles, or the name of the profile directly (if profile not using roles). This allows the session token credentials to be
re-used across multiple roles configured to use the same source profile configuration.

If using MFA, when the cached credentials approach expiration you will be prompted to re-enter the MFA token value to
refresh the credentials during the next execution of aws-runas. (Since this is a wrapper program, there's no way to know
when credentials need to be refreshed in the middle of the called program execution) If MFA is not required for the assumed
role, the credentials should refresh without user intervention when aws-runas is next executed.

There are no external libraries, or language or runtime dependencies, necessary to run the program. The compiled
platform-specific executables contain everything necessary to just download the file, do a small bit of setup and you're
off and running.