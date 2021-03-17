---
title: SAML Configuration Guide
---
This page provides a deeper look at the configuration used by aws-runas with SAML single sign-on integration.  One
benefit of the SAML capability is that there is no requirement to store a set of static AWS credentials on the system,
with the drawback of needing to be an engaged participant in the SAML authentication process (supplying username, password
and any necessary multi-factor actions).  This page is meant as a generic configuration reference for using aws-runas
with SAML authentication.  For information about the configuration for a specific SAML provider (Okta, Keycloak, etc)
see the [SAML Client Configuration Guide]({{ "saml_client_config.html" | relative_url }})


### Configuration File
The configuration file is an ini-formatted file used to store AWS profile configuration. By default, the AWS SDK looks
for a file name 'config' in a directory called .aws inside a user's home directory. If you need to use a non-default
configuration file location, you can set the `AWS_CONFIG_FILE` environment variable to the location of the file on the
system.

To use aws-runas effectively, especially if you use multiple roles, it's advisable to set up profiles using this file.

#### Default Section
The configuration file should contain a `[default]` section, where top-level/global configuration is set.  Per-profile
values can still be set in each profile's section, which will be preferred over settings in the default section.

A simple default section could look something like:

```text
[default]
region = us-east-1
```

However, only having a default section won't make aws-runas a very useful tool, read the section below about configuring
profiles to learn how to configure a profile for assuming a role.

#### Profile Sections
Profile sections in the configuration file are what is used to provide the settings used to assume a role using SAML
integration with aws-runas.  Since the SAML integration configuration is specific to aws-runas, and not part of the
larger AWS tool ecosystem, the configuration shown here would not be leveraged by tools such as the awscli.

The minimum profile configuration required for assuming a role using SAML looks like this:

```text
[profile my-profile]
saml_auth_url = https://example.org/saml/auth
role_arn = arn:aws:iam::012345678901:role/my-role
```

This configures a profile named 'my-profile' to assume a role called 'my-role' in the fictitious AWS account
012345678901, using the credentials obtained from the SAML identity provider identified in the `saml_auth_url` attribute.
One thing to make note of is the word 'profile' before the actual profile name in the section heading (the stuff between
the [] brackets), this is an oddity of the logic AWS uses to process the config file, and is necessary for any non-default
profile you'll configure.

If the SAML authentication flow requires that you use multi-factor authentication, you will be prompted to perform the MFA
action, depending on which types of multi-factor authentication are supported by the identity provider, and configured
for the user's account.

A profile's configuration also allows you to override settings set in the default profile, or the configuration in the
profile referenced in the 'source_profile' attribute. For example, if the default section configures the region as
'us-east-1' (like above), you can set the region attribute inside the profile configuration, which will override the
default value when using that profile.

If you have multiple profiles configured, all using the same saml_auth_url, it can become tedious, and redundant, to copy
the saml_auth_url attribute between all the profiles. The aws-runas tool supports setting common configuration for SAML
attributes in the profile referenced in the source_profile attribute, or in the default section.

The following example demonstrates how to set up the .aws/config file using the common saml_auth_url attribute, which will
be used for every profile.  If you interact with multiple identity providers when accessing AWS, or use a mix of SAML and
IAM configured profiles, it is advisable to not configure the `saml_auth_url` in the default profile.  A better practice
is to configure a common, non-default profile which has configuration specific to a group of profiles requiring that
configuration.

```text
[default]
region = us-east-1
saml_auth_url = https://example.com/saml/auth

[profile my-role]
source_profile = default
role_arn = arn:aws:iam::012345678901:role/my-role

[profile other-role]
region = us-west-2
source_profile = default
role_arn = arn:aws:iam::567890123456:role/other-role
```

#### Custom Configuration File Attributes
In addition to the required parameters shown above, the program supports other configuration attributes for the profiles
defined in the .aws/config file for using SAML integration. These attributes are specific to aws-runas and will be
ignored by other tools leveraging the AWS SDK.

* `saml_username` This attribute sets the username to use when performing SAML authentication.  If not set, aws-runas
  will prompt for the value to be input via the command line.
* `saml_provider` This attribute allows you to explicitly specify the SAML provider to use, and bypass the auto-detection
  logic.  This may be useful for cases where the auto-detection logic fails, or is blocked by a CDN or WAF.  The value is
  treated as case-insensitive, but must be one of the supported providers, otherwise aws-runas will fail
  with the error: `panic: unable to determine client provider type`
* `jump_role_arn` For cases where you will perform SAML authentication to assume an initial (jump) role to retrieve
  credentials which allow you to assume a role in the target AWS account, configure this value with the role ARN needed
  for the initial role.  Your AWS IAM or identity provider administrator should know if you need to configure this
  attribute, and the value to set.
* `credentials_duration` This attribute specifies the lifetime of the assume role credentials requested by aws-runas.
  Except for a narrow set of cases, it's usually safe to leave this setting at the default value of 1h. Valid
  values are between 15m and 12h, however setting this value above the default 1h requires the IAM role in AWS to be
  configured to allow the extended duration. Attempts to set a duration longer than the IAM role can support will cause
  aws-runas to fail with an error.
* `mfa_type` Use this attribute to force a specific MFA type instead of the provider auto-detection logic.

Values for the `credentials_duration` property are specified as golang time.Duration strings.
(See [https://golang.org/pkg/time/#ParseDuration](https://golang.org/pkg/time/#ParseDuration) for more info)  The scope
of these settings are determined by where they are set in the profiles.  The most specific setting is used, so a value
specified in a role profile will be used instead of a value defined in the default section.


### SAML Credentials
There are multiple ways to provide a SAML password to aws-runas for you to authenticate with the identity provider.  If
none of the below methods are used, aws-runas will prompt for the password when required.

#### Credentials File (preferred)
A password can be set in the AWS credentials file, which will be used if neither the command line option, nor environment
variable are detected.  This is the most secure way to use a password for an external identity provider with aws-runas,
as the value stored in the credentials file is obfuscated to keep the raw value out of the file.  This is no more or less
secure than storing a set of static AWS credentials in the file, as is the case with non-SAML profiles.

To set a password in the credentials file, run `aws-runas password <profile>`, substituting the SAML-enabled profile name
for \<profile\>.  This will prompt you for the password value, and write the obfuscated information to the credentials file.

If the password for the identity provider is changed, you are required to update aws-runas using the `aws-runas password ...`
command, otherwise the old password value is used, and the authentication will fail. There is a risk of locking out your
account in the identity provider if there are too many authentication failures. (This behavior is specific to the settings
of the identity provider, work with your identity provider administrator for more information.)

#### Command Line Option
The `-P` option allows you to specify the password directly on the command line.  This is the least secure way to
provide the password, as anyone on the system can inspect the options used by the command and see the raw password value.

#### Environment Variable
Setting the `SAML_PASSWORD` environment variable will pass the value to aws-runas to as the password for authentication.
This is slightly more secure than the `-P` flag, but anyone on the system capable of viewing the running program's
environment will be able to see the raw password value.


### Environment Variables
Standard AWS SDK environment variables are supported by this program. (See
[https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/config#EnvConfig](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/config#EnvConfig))
Most will be passed through to the calling program except for the `AWS_PROFILE` environment variable, which will be explicitly
unset before aws-runas executes the program supplied as an argument to aws-runas. (It only affects the environment
variable for the execution of aws-runas, the setting in the original environment is unaffected)  If your code relies on
the value of that `AWS_PROFILE` environment variable, it will be reflected to the program under a new environment
variable called `AWSRUNAS_PROFILE`

If the `AWS_PROFILE` environment variable is set, it will be used in place of the 'profile' argument to the command. In
this example, the 'aws s3 ls' command will be executed using the profile 'my_profile'

```text
$ AWS_PROFILE=my_profile aws-runas aws s3 ls
```

Additionally, the custom config attributes mentioned above are also available as the environment variables
`CREDENTIALS_DURATION`, `SAML_AUTH_URL`, `SAML_USERNAME`, `SAML_PROVIDER`, `JUMP_ROLE_ARN`, and `MFA_TYPE`


### Additional References
See the following for more information on AWS SDK configuration files:

* [http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html](http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html)
* [https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration](https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration)
* [https://boto3.readthedocs.io/en/latest/guide/configuration.html#aws-config-file](https://boto3.readthedocs.io/en/latest/guide/configuration.html#aws-config-file)
