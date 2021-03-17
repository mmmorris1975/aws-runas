---
title: IAM Configuration Guide
---
This page provides a deeper look at the credentials and config files used by aws-runas with IAM user credentials,
and some custom parameters you can use to configure the tool.

### Credentials File
The credentials file is an ini-formatted file used to store the AWS access and secret keys.  The keys in this file should
be secured just like you would any other file containing passwords or other sensitive information.  By default, the AWS
SDK looks for a file named 'credentials' in a directory called .aws inside your user's home directory.  If you need to
use a non-default credentials file location, you can set the `AWS_SHARED_CREDENTIALS_FILE` environment variable to the
location of the file on the system.

This file needs to contain at least 1 section, identified by the `[default]` section heading. This will contain the
access and secret key values used with requests to AWS.  These credentials will be used for any profile in the
configuration file which sets `source_profile = default`, or any other case where there are not other credentials available.

```text
[default]
aws_access_key_id     = AKIAMYACCESSKEY
aws_secret_access_key = MySecretKey
```

The example above shows the minimum configuration necessary for the credentials file.  Replace the values on the right
side of the '=' with your particular AWS keys.

If you need to operate in multiple AWS accounts which use distinct IAM credentials for access, then you can add another
section in the credentials file to set the credentials to use for that profile. For example, if you have a set of work
AWS credentials you use as your default, and a set of personal AWS credentials you use away from the office, you can
configure another profile section (in addition to the default one).

```text
[personal]
aws_access_key_id     = AKIAMYPERSONALKEY
aws_secret_access_key = MyPersonalSecretKey
```

These 'personal' credentials would be used if you set the environment variable `AWS_PROFILE=personal` or you have a
profile which sets `source_profile = personal` in the configuration file.


### Configuration File
The configuration file is an ini-formatted file used to store AWS profile configuration. By default, the AWS SDK looks
for a file name 'config' in a directory called .aws inside a user's home directory. If you need to use a non-default
configuration file location, you can set the `AWS_CONFIG_FILE` environment variable to the location of the file on the
system.

To use aws-runas effectively, especially if you use multiple roles, it's advisable to set up profiles using this file.

#### Default Section
Like the credentials file, the configuration file should also configure a `[default]` section, where top-level/global
configuration is set.  Per-profile values can still be set in each profile's section, which will be preferred over
settings in the default section.

A simple default section could look something like:

```text
[default]
region = us-east-1
```

However, only having a default section won't make aws-runas a very useful tool, read the section below about configuring
profiles to learn how to configure a profile for assuming a role.

#### Profile Sections
Profile sections in the configuration file are used to provide the settings used to assume a role with aws-runas, or
other tools which support assuming roles using this file.

The minimum profile configuration required for assuming a role looks like this:

```text
[profile my-profile]
source_profile = default
role_arn = arn:aws:iam::012345678901:role/my-role
```

This configures a profile named 'my-profile' to assume a role called 'my-role' in the fictitious AWS account
012345678901, using the credentials found in the default section of the credentials file.  One thing to make note of is
the word 'profile' before the actual profile name in the section heading (the stuff between the [] brackets), this is an
oddity of the logic AWS uses to process the config file, and is necessary for any non-default profile you'll configure.

If the role requires that you use MFA, then you will need to configure an attribute named `mfa_serial` in the profile,
which contains the ARN value of the MFA device you configured for your IAM account. If you have a properly configured
.aws/credentials file, you can find this value by running `aws-runas -m`, or under your IAM user's configuration in the
AWS console.  The [Quick Start Guide]({{ "quickstart.html#configuration-file" | relative_url }}) provides an example of
what a profile configured to use MFA would look like.

A profile's configuration also allows you to override settings set in the default profile, or the configuration in the
profile referenced in the 'source_profile' attribute. For example, if the default section configures the region as
'us-east-1' (like above), you can set the region attribute inside the profile configuration, which will override the
default value when using that profile.

If you have multiple profiles configured, all using the same source_profile and mfa_serial configuration, it can become
tedious, and redundant, to copy the mfa_serial attribute between all the profiles. The aws-runas tool supports a
non-standard configuration for the mfa_serial attribute by specifying the setting in the profile referenced in the
source_profile attribute, or in the default section. This configuration is non-standard in that other tools (like the
awscli) which read the .aws/config file will not recognize the mfa_serial attribute configured outside a role profile,
and will not prompt you for the MFA code. One example of this would be using the awscli tools with the --profile option,
as that is expecting the mfa_serial attribute to be present in the role profile if it is required for the role. However,
if your workflow revolves around using aws-runas there should be no harm using this non-standard setup.

The following example demonstrates how to set up the .aws/config file using the common mfa_serial attribute. With this
configuration the my-role and other-role profiles (and any other profile) will use the specified mfa_serial attribute
when performing the assume role operation.    
**NOTE** While this is a supported configuration, it isn't necessarily the best practice.  With this configuration, every
profile will use the configured mfa_serial when trying to assume a role.  If you need to use roles outside a centralized
IAM identity, this will likely result in failure when assuming those roles.  A better practice is to configure a common,
non-default profile which has configuration specific to a group of profiles requiring that configuration.

```text
[default]
region = us-east-1
mfa_serial = arn:aws:iam::9876543221098:mfa/my_iam_user

[profile my-role]
source_profile = default
role_arn = arn:aws:iam::012345678901:role/my-role

[profile other-role]
region = us-west-2
source_profile = default
role_arn = arn:aws:iam::567890123456:role/other-role
```


#### Custom Configuration File Attributes
The program supports custom configuration attributes in the profiles defined in the .aws/config file to set non-default
session token and assume role credential lifetimes. These attributes are specific to aws-runas and will be ignored by
other tools leveraging the AWS SDK. Values for these attributes are specified as golang time.Duration strings.
(See [https://golang.org/pkg/time/#ParseDuration](https://golang.org/pkg/time/#ParseDuration) for more info)  The scope
of these settings are determined by where they are set in the profiles.  The most specific setting is used, meaning a value
specified in a role profile will be used instead of a value defined in the default section.

* `session_token_duration` This attribute specifies the lifetime of the session token credentials (which carry the MFA
  information). This would be the setting to adjust for most cases, since it determines the interval which the session
  token credentials (and by extension, any MFA code entry) will be refreshed.  Valid values are between 15m and 36h,
  with the default value of 12h.
* `credentials_duration` This attribute specifies the lifetime of the assume role credentials requested by aws-runas.
  Except for a narrow set of cases, it's usually safe to leave this setting at the default value of 1h. Valid
  values are between 15m and 12h, however setting this value above the default 1h requires the IAM role in AWS to be
  configured to allow the extended duration. Attempts to set a duration longer than the IAM role can support will cause
  aws-runas to fail with an error. One side effect of increasing this lifetime beyond 1h is that assume role
  credentials must be directly requested from AWS, using the IAM user credentials instead of session token credentials.
  For roles requiring MFA, this means that the MFA code will need to be entered each time the assume role credentials expire,
  which is typically a shorter interval than using session token credentials to perform the assume role operation.


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
`SESSION_TOKEN_DURATION` and `CREDENTIALS_DURATION`


### Additional References
See the following for more information on AWS SDK configuration files:

* [http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html](http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html)
* [https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration](https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration)
* [https://boto3.readthedocs.io/en/latest/guide/configuration.html#aws-config-file](https://boto3.readthedocs.io/en/latest/guide/configuration.html#aws-config-file)
