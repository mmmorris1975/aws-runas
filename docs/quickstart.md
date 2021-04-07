---
title: Quick Start Guide
---

This document will walk you through the basic installation and configuration of the tool to hopefully get you up
and running quickly

### Installation

<a href="{{ site.github.repository_url }}/releases/latest" target="_blank">Download the latest release</a>, using the
zip file appropriate for the system you are running the tool on.  Supported platforms are:

  * MacOS
    * 64-bit Intel (aws-runas-\<version\>-darwin-amd64.zip)
    * M1/Arm (aws-runas-\<version\>-darwin-arm64.zip)
  * Windows
    * 64-bit Intel (aws-runas-\<version\>-windows-amd64.zip)
  * Linux
    * 64-bit Intel (aws-runas-\<version\>-linux-amd64.zip)
    * ARMv7 (aws-runas-\<version\>-linux-arm.zip)
    * Arm64 (aws-runas-\<version\>-linux-arm64.zip)

For Linux, DEB and RPM packages are also available for each supported architecture.

If you do not see a download for your system, create a new issue <a href="{{ site.github.issues_url }}" target="_blank">here</a>,
and we'll work on getting the appropriate build created for you.

#### MacOS and Linux

If you are using the DEB or RPM package for Linux, no additional work is required other than installing the package.

If using the ZIP file, unzip it and move the extracted `aws-runas` file to a location in your PATH, so you can execute
the command without having to provide the full path to the file. Many people will simply create a bin directory inside
their home directory (`mkdir ~/bin`), and add that to their shell's PATH, so they have a locally-controlled directory
containing their individual tooling.

##### Shell completion
Tab completion for bash and zsh is supported in aws-runas. Using the DEB and RPM packages automatically installs the
completion logic in a system-wide location.  When using the zip file to install aws-runas, you will need to manually
configure the command completion.

###### Bash auto-complete
To configure auto-completion at a system-wide level, install the file from the
[git repository]({{ site.github.repository_url }}/tree/master/extras/aws-runas-bash-completion)
as a file named `/etc/bash_completion.d/aws-runas` on the local system.  If you only want to install the auto-completion
for some users, download that same file, and in the user's .bashrc add the following lines:

```shell
PROG=aws-runas
source /path/to/aws-runas-bash-completion
```

###### Zsh auto-complete
To configure auto-completion when using zsh, download the file from the
[git repository]({{ site.github.repository_url }}/tree/master/extras/aws-runas-zsh-completion),
and in the user's .zshrc add the following lines:

```shell
PROG=aws-runas
_CLI_ZSH_AUTOCOMPLETE_HACK=1
source /path/to/aws-runas-zsh-completion
```

#### Windows

After downloading the ZIP file, unzip it and move the extracted `aws-runas.exe` file to a location where it is
easily accessible, like on the desktop, or in your home directory.

### Configuration

Both the AWS credentials and configuration files live in a directory named `.aws` in your user's home directory.  On
Windows, this is `%USERPROFILE%\.aws` and on MacOS and Linux, this would be `$HOME/.aws`.  Create this directory if it
does not already exist.

### IAM
When using an AWS IAM user to assume a role, the sections below are the minimal setup required to configure a profile for
a role in the configuration file. The first thing you'll want to do is configure your IAM user credentials in the appropriate
file so the tools can call the necessary AWS APIs.

#### Credentials File
Using the text editor of your choice, create a file named `credentials` in the .aws folder in your home directory.  In
this file, paste the following bit of text:

```text
[default]
aws_access_key_id     = MY_AWS_ACCESS_KEY_GOES_HERE
aws_secret_access_key = MY_AWS_SECRET_KEY_GOES_HERE
```

The values for the items on the right side of the '=' sign can be obtained by logging in to the AWS console, navigating
to your user account in the IAM service console, selecting the 'Security credentials' tab, and clicking on the
'Create access key' button.  Copy and paste the provided values at the appropriate place in the file, save the data,
and exit.

On MacOS and Linux systems, it would be advisable to chmod this file to only be accessible to your user, since these
keys are secure credentials used to access the AWS API. Running `chmod 600 ~/.aws/credentials` should do the trick.

#### Configuration File
Using the text editor of your choice, create a file named `config` in the .aws folder in your home directory.  In
this file, paste the following bit of text, save the file, and exit:

```text
[default]
region = us-east-1
```

The above data is enough to allow you to use aws-runas to list some of the IAM roles you have access to (the '-l' option),
to find your MFA device ARN (if required, using the '-m' option), or create a set of session token credentials (the '-s'
option).  However, it isn't enough to make aws-runas assume a role and provide you access to AWS resources outside of
the account where your IAM user is managed.

To configure a role for aws-runas to assume, re-open the config file in your text editor, and create a profile.  It
should look something like this:

```text
[profile my-profile]
source_profile = default
role_arn       = arn:aws:iam::012345678901:role/my-role
mfa_serial     = arn:aws:iam::9876543221098:mfa/my_iam_user
```

This will create a profile called "my-profile", which is configured to assume a role called "my-role". The "source_profile"
line is critical, as it tells tools making AWS API calls (like aws-runas) to use the credentials in the credentials file
under that section name. The value for role_arn can be found by running `aws-runas -l` and selecting a value from that.
The "mfa_serial" line is optional, you should know whether you need to have that configured (your IAM administrators
should be able to give you the answer).  If you do not need to have MFA, then you can delete this line.  Otherwise, you
should configure this value with the data returned from running `aws-runas -m` (after configuring the MFA device for
your IAM user, of course!)

Create a profile section for each role you want to assume in AWS, and you should be well on your way!

### SAML

If enabled for your AWS account(s), you can configure aws-runas to leverage SAML single sign-on and authenticate against
your organizations identity provider and perform the necessary handshaking with AWS to perform the Assume Role With SAML
operation based on the authorizations granted by your identity provider.  To configure a profile for SAML, you will only
need to define the profile parameters in the `config` file in the .aws folder in your home directory.  You can optionally
set your identity provider password in the `credentials` file as well.

Each SAML identity provider has their own process for handling authentication of a user and integrating with multi-factor
authentication.  This means that aws-runas can't magically support every SAML provider.  If you find a case where your
identity provider is not yet supported by the tool, open a Github issue, and we'll look at adding support for it.

To set up a simple SAML-integrated profile, you should be able to copy and paste the snippet below while editing the
config file:

```text
[profile my-profile]
saml_auth_url = https://example.org/saml/auth
saml_username = my-user-name
role_arn      = arn:aws:iam::1234567890:role/MyRole
```

You'll need to modify all the values to the right of the `=` with the values specific to your organization.
The `saml_auth_url` parameter is the URL of the authentication endpoint for yor specific identity provider.  The `role_arn`
parameter is the AWS ARN of the IAM role you will assume after the SAML authentication is complete.  You should be able to
get the necessary values for both of these parameters from the person or team responsible for managing your AWS accounts.
The `saml_username` parameter is optional, but is a handy shortcut to supply your username to the SAML provider, instead
of getting prompted for it each time you need to authenticate to your SAML identity provider.

If you do not configure a password for your identity provider, you will be prompted to enter it when aws-runas is required
to authenticate with the identity provider.  To skip this prompting, you can configure aws-runas to store your password
in an obfuscated form using the `aws-runas password my-profile` command.  You will be prompted to enter your password for
the identity provider, and the value will be stored in the `.aws/credentials` file.  If this password changes, you will
need to re-run this step and provide the new password, otherwise aws-runas will fail, and you potentially risk locking
your account in your organization's identity provider.

### Web Identity

If enabled for your AWS account(s), you can configure aws-runas to leverage OIDC single sign-on and authenticate against
your organizations identity provider and perform the necessary handshaking with AWS to perform the Assume Role With Web Identity
operation based on the authorizations granted by your identity provider.  To configure a profile for Web Identity (OIDC),
you will only need to define the profile parameters in the `config` file in the .aws folder in your home directory.  You
can optionally set your identity provider password in the `credentials` file as well.

Each OIDC identity provider has their own process for handling authentication of a user and integrating with multi-factor
authentication.  This means that aws-runas can't magically support every provider.  If you find a case where your identity
provider is not yet supported by the tool, open a Github issue, and we'll look at adding support for it.

To set up a simple Web Identity-integrated profile, you should be able to copy and paste the snippet below while editing
the config file:

```text
[profile my-profile]
web_identity_auth_url     = https://example.org/oauth2
web_identity_username     = my-user-name
web_identity_client_id    = theClientID
web_identity_redirect_uri = app:/callback
role_arn                  = arn:aws:iam::1234567890:role/MyRole
```

You'll need to modify all the values to the right of the `=` with the values specific to your organization.
The `web_identity_auth_url` parameter is the URL of the authentication endpoint for yor specific identity provider. The
`web_identity_client_id` and `web_identity_redirect_uri` parameters are OIDC-specific configuration for your identity
provider.  The `role_arn` parameter is the AWS ARN of the IAM role you will assume after the OIDC authentication is complete.
You should be able to get the necessary values for all of these parameters from the person or team responsible for managing
your AWS accounts.  The `web_identity_username` parameter is optional, but is a handy shortcut to supply your username
to the OIDC provider, instead of getting prompted for it each time you need to authenticate to your OIDC identity provider.

If you do not configure a password for your identity provider, you will be prompted to enter it when aws-runas is required
to authenticate with the identity provider.  To skip this prompting, you can configure aws-runas to store your password
in an obfuscated form using the `aws-runas password my-profile` command.  You will be prompted to enter your password for
the identity provider, and the value will be stored in the `.aws/credentials` file.  If this password changes, you will
need to re-run this step and provide the new password, otherwise aws-runas will fail, and you potentially risk locking
your account in your organization's identity provider.

### Running

At this point, we should have enough configuration to execute aws-runas with some level of success. The aws-runas tool
is designed to be a command-line driven utility, so you'll need to fire up your command prompt or terminal emulator to
use the tool. Using the example configuration above, you should be able to execute the command like:

```text
> aws-runas my-profile
```

if you are required to use MFA, you will be prompted to enter your MFA code. Then you should see output similar to:

```text
export AWS_REGION='us-east-1'
export AWS_DEFAULT_REGION='us-east-1'
export AWS_ACCESS_KEY_ID='ASIAROLEACCESSKEY'
export AWS_SECRET_ACCESS_KEY='RoleSecretKey'
export AWS_SESSION_TOKEN='RoleSessionToken'
```
The AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN values will be some nonsensical string, particular
to the set of credentials AWS generated for you.  On Windows, the leading "export" will say "set" instead to allow the
returned values to be set as environment variables in your command line session.  This is a simple test to validate that
the configuration is correct.

If you have the awscli command line tools installed, you can use aws-runas to call the awscli tools.  The following
example shows how to use aws-runas to list the S3 buckets in the account for the role (assuming your role grants you the
permissions to list S3 buckets).  
`aws-runas my-profile aws s3 ls`