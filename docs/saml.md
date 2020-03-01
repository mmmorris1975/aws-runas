---
layout: page
title: SAML Configuration Guide
---
# SAML Configuration Guide
This page provides a more in-depth look at the config file used by aws-runas with SAML single sign-on integration.  One
benefit of the SAML capability is that there is no requirement to store a set of static AWS credentials on the system,
with the drawback of needing to be an engaged participant in the SAML authentication process (supplying username, password
and any necessary multi-factor actions). 


### Configuration File
The configuration file is an ini-formatted file used to store AWS profile configuration. By default, the AWS SDK looks
for a file name 'config' in a directory called .aws instance of a user's home directory. If you need to use a non-default
configuration file location, you can set the `AWS_CONFIG_FILE` environment variable to the location of the file on the
system.

To use aws-runas effectively, especially if you use multiple roles, it's advisable to set up profiles using this file.


#### Default Section
The configuration file should configure a `[default]` section, where top-level configuration is set.  Per-profile
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
larger AWS tool ecosystem, the configuration showed here would not be leveraged by tools like the awscli.

The minimum profile configuration required for assuming a role using SAML looks like this:

```text
[profile my-profile]
saml_auth_url = https://example.org/saml/auth
role_arn = arn:aws:iam::012345678901:role/my-role
```

This configures profile called 'my-profile' to assume a role called 'my-role' in the fictitious AWS account number
012345678901 using the credentials obtained from the SAML identity provider identified in the `saml_auth_url` attribute. 
One thing to make note of is the word 'profile' before the actual profile name in the section heading (the stuff between
the [] brackets), this is an oddity of the logic AWS uses to process the config file, and is necessary for any non-default
profile you'll configure.

If the SAML authentication flow requires that you use multi-factor authentication, you will be prompted to perform the MFA
action, depending on which types of multi-factor authentication is supported by the identity provider.

A profile's configuration also allows you to override settings set in the default profile. For example, if the default
section configures the region as 'us-east-1' (like above), you can set the region attribute inside the profile configuration,
which will override the default value when using that profile.

If you have multiple profiles configured, all using the same saml_auth_url, it can become tedious, and redundant, to copy
the saml_auth_url attribute between all of the profiles. The aws-runas tool configure the setting in the profile referenced
in the source_profile attribute, or in the default section.

The following example demonstrates how to set up the .aws/config file using the common saml_auth_url attribute

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
In addition to the required parameters shown abive, the program supports other custom configuration attributes in the profiles
defined in the .aws/config file to other configuration for using SAML integration. These attributes are specific to aws-runas
and will be ignored by other tools leveraging the AWS SDK.

  * `saml_username` This attribute sets the username to use when performing the SAML authentication.  If not set, aws-runas
    will prompt for the value to be input via the command line.
  * `jump_role_arn` For cases where you will perform SAML authentication to assume an initial (jump) role to retrieve
    credentials which allow you to assume a role in the target AWS account, configure this value with the role ARN needed
    for the initial role.
  * `session_token_duration` This attribute specifies the lifetime of the SAML SessionDuration property which is passed
    to AWS after a successful SAML authentication.
  * `credentials_duration` This attribute specifies the lifetime of the assume role credentials requested by aws-runas.
    With the exception of a narrow set of cases, it's usually safe to leave this setting at the default value of 1h. Valid
    values are between 15m and 12h, however setting this value above the default 1h requires the IAM role in AWS to be
    configured to allow the extended duration. Attempts to set a duration longer than the IAM role can support will cause
    aws-runas to fail with an error.

Values for the `session_token_duration` and `credentials_duration` properties are specified as golang time.Duration strings.
(See [https://golang.org/pkg/time/#ParseDuration](https://golang.org/pkg/time/#ParseDuration) for more info)  The scope
of these setting is determined by where they are set in the profiles.  The most specific setting is used, so a value
specified in a role profile will be used instead of a value defined in the default section.


### SAML Credentials
There are multiple ways to provide a SAML password to aws-runas so that you can successfully authenticate to the identity
provider.

#### Command Line Option
The `-P` option allows you to specify the SAML password directly on the command line.  This is the least secure way to
provide the password, as anyone on the system can inspect the options used by the command and see the raw password value.

#### Environment Variable
Setting the `SAML_PASSWORD` environment variable will pass the value to aws-runas to use for SAML authentication.  This
is slightly more secure than the `-P` flag, but anyone on the system capable of viewing the running program's environment
will be able to see the raw password value.

#### Credentials File (preferred)
A password can be set in the AWS credentials file, which will be used if neither the command line option, or environment
variable are detected.  This is the most secure way to use a SAML password with aws-runas, as the value stored in the
credentials file is obfuscated to keep the raw value out of the file.  This is no more or less secure then storing a set
of static AWS credentials in the file, as is the case with non-SAML profiles.

To set a password in the credentials file, run `aws password <profile>`, substituting the SAML-enabled profile name for
\<profile\>.  This will prompt you for the password value, and write the obfuscated information to the credentials file.


### Environment Variables
Standard AWS SDK environment variables are supported by this program. (See the `Environment Variables` section in 
[https://docs.aws.amazon.com/sdk-for-go/api/aws/session/](https://docs.aws.amazon.com/sdk-for-go/api/aws/session/))
Most will be passed through to the calling program except for the `AWS_PROFILE` environment variable which will be explicitly
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
`SESSION_TOKEN_DURATION` and `CREDENTIALS_DURATION`


### Bash Shell Completion
To get tab completion for profile names in the bash shell, download and install the
<a href="{{ site.github.repository_url}}/blob/master/extras/aws-runas-bash-completion" target="_blank" download>extras/aws-runas-bash-completion</a>
script from the code repository and install it in your bash_completion.d directory or add the following line to your bashrc:

```text
source path/to/extras/aws-runas-bash-completion
```


### Additional References
See the following for more information on AWS SDK configuration files:

  * [http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html](http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html)
  * [https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration](https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration)
  * [https://boto3.readthedocs.io/en/latest/guide/configuration.html#aws-config-file](https://boto3.readthedocs.io/en/latest/guide/configuration.html#aws-config-file)
