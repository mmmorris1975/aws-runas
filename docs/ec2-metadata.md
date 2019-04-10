---
layout: page
title: EC2 Metadata Service
---
# EC2 Metadata Service
The EC2 Metadata Service feature of aws-runas allows you to run a local web server which mimics the credential retrieval
abilities of the EC2 metadata service which runs on AWS EC2 instances. In place of an EC2 instance profile, aws-runas
will serve the assume role credentials of the provided profile.

This will enable use cases where a developer wishes to execute their code via an IDE, but it's cumbersome to setup the
execution environment to use aws-runas in the traditional "wrapper" mode.


## Important Notes
In order to run aws-runas using the EC2 metadata service mode, you will need to execute it with administrative access to
configure a network interface, and setup the HTTP listening port. This means that you will need to execute the aws-runas
using `sudo` on Linux or MacOS, or with Administrator privileges on Windows. While not ideal, it is the most portable way
to configure a system to listen on the AWS hard-coded endpoint of http://169.254.169.254 for serving the metadata.  On
non-Windows systems, root-level permissions are dropped back to the identity of the calling user as soon as the network
interface and port are configured.  In addition to being a security best-practice, this also helps to keep the ownership
of the credential cache files sane, and not only owned and accessible by the root user.

Also be aware that this is not a full-blown implementation of the EC2 metadata service, it only exposes the paths
used to obtain IAM role credentials from an EC2 instance profile. It also exposes some paths which are not part of the
EC2 metadata service so we can adjust the configuration of the service while it is running.

## Running
To execute aws-runas using the EC2 Metadata Service feature, use the `--ec2` flag when running the command. For example,
on a MacOS or Linux system:

```text
$ sudo ./aws-runas --ec2 my-role
```

If you are required to use MFA for the role, and it is unable to find any valid cached credentials, you will be prompted
to enter the MFA code on the command line. Once all of that out of the way, you should see messages similar to:

```text
2019/04/01 12:34:56 INFO POST /profile HTTP/1.1 200 29
2019/04/01 12:34:56 INFO EC2 Metadata Service ready on http://169.254.169.254:80 using initial profile 'my-role'
```

The program will continue to run in the foreground and log messages about the HTTP calls made to the service in a quasi
http access log format.


## Program Access
When executing programs which will get their credentials via this local metadata service, it may be necessary to set the
`AWS_SHARED_CREDENTIALS_FILE` environment variable to an invalid value so the SDK does not attempt to use the credentials
in that file to make the AWS service calls. This is due to the default AWS credential lookup chain checking the credentials
file before attempting to get the credentials via the metadata service.

For example, running:
```text
$ aws s3 ls
```

Will likely not connect to the metadata service for credentials, and instead use the credentials configured in the default
section in the .aws/credentials file. That means the example above will return an S3 bucket listing for the AWS account
managing the default credentials, instead of the account which is configured for the role and profile which is active in
the metadata service. One way to get around this will be to run the command like this instead (after starting the metadata service):

```text
$ AWS_SHARED_CREDENTIALS_FILE=/dev/null aws s3 ls
```


## Browser Interface
Starting with the 1.3 release, the aws-runas EC2 Metadata Service feature provides a web interface for managing the
active profile used to retrieve credentials with the service. It can be accessed by pointing your web browser at
http://169.254.169.254/ after starting the process from the command line.

Below is a screenshot of the metadata service interface, and is the only screen available.
![Metadata Service Browser Interface](/assets/images/metadata-web-iface.png)

The 'Roles' drop down will contain a list of roles available in the .aws/config file to select from. Selecting a role from
the list will automatically switch the active role in the service, there is no requirement to submit or refresh after
selecting a role from the drop down list. Once a role is selected, if a valid set of credentials is available from the
cache, it will display the local date and time the credentials will expire. If the selected role requires a fresh set of
credentials, and requires using MFA, then you will receive a popup dialog for you to enter your MFA code. The dialog will
appear similar to the following screen shot...

![Metadata Service Browser Interface MFA Dialog](/assets/images/metadata-web-mfa.png)

The 'Refresh Now' is not used as part of the normal workflow in the browser interface. It is provided as a way to force
a refresh of the credentials used for the role. After clicking this button, you will be required to re-submit the current
MFA code for the active profile, if the role requires the use of MFA. If MFA is not required, a new set of credentials
will be obtained with no other intervention required.


## API Endpoints
Below is a breakdown the endpoints available in the aws-runas EC2 Metadata Service, and the HTTP operations they support.

#### AWS standard endpoints
`/latest/meta-data/iam/security-credentials/` - Performing an HTTP GET against this path will return the name of the currently
active profile name which will be used to retrieve the credentials.  This is part of the flow the AWS SDKs use for retrieving
credentials from the actual EC2 metadata service. Accessing this path on a real EC2 instance with an instance profile
configured will return the name of the instance profile set on the instance.

Example:
```text
$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
my-role
```

`/latest/meta-data/iam/security-credentials/<profile>` - Performing an HTTP GET against this path, using the name of the
profile returned from a GET call to the path above, will return a set of role credentials in the JSON format expected by
the AWS SDK when retrieving credentials from the actual EC2 metadata service. Accessing this path on a real EC2 instance,
using the instance profile name, will return the currently active role credentials for the instance.

Example:
```text
$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/my-role
{"Code":"Success","LastUpdated":"2019-04-02T01:02:03Z","Type":"AWS-HMAC","AccessKeyId":"ASIANOTAKEY","SecretAccessKey":"MySecretKey","Token":"SessionTokenValue","Expiration":"2019-04-02T01:23:45Z"}
```

#### aws-runas specific endpoints
`/list-roles` - An HTTP GET against this path will return a JSON formatted list of the available roles configured in
your local .aws/config file.

Example:

```text
$ curl http://169.254.169.254/list-roles
["my-role", "my-other-role", "my-admin-role"]
```

`/profile` - An HTTP GET against this path will return the name of the currently active profile used to retrieve the
credentials.

GET example:
```text
$ curl http://169.254.169.254/profile
my-role
```

An HTTP POST to this path, providing a valid role name in the request body, will change the active profile
used to retrieve the role credentials. The POST call will return HTTP 200, and the response body will contain the system
local time when the credentials will expire, if it was able to successfully obtain a set of credentials for the role. The
POST call will return HTTP 401 if it was unable to retrieve the credentials because they have expired, and require MFA
to get a fresh set of credentials.

POST example:
```text
$ curl -d my-other-role http://169.254.169.254/profile
2019-01-02 03:04:56 -0500 CDT
```

`/mfa` - An HTTP POST to this path, providing the MFA code in the request body, will update the session credential
provider used by the service and obtain a fresh set of session token credentials for the currently configured profile.
Making a call to this endpoint is typically done in response to an HTTP 401 status code returned from the /profile path
of the service so that a new set of credentials with a valid MFA code can be obtained.  A successful call will return an
HTTP 200 status, and the response body will contain the system local time when the credentials will expire.

Example:
```text
$ curl -d 123456 http://169.254.169.254/mfa
2019-01-02 03:04:56 -0500 CDT
```

`/refresh` - An HTTP post to this path will force a refresh of the credentials used by the currently active profile, any
data in the request body will be ignored. This will cause the next call to get credentials to fail with an HTTP 401 status,
if MFA is required to assume the role.  If successful, it will return an HTTP 200 status, and the response body will contain
the text 'success'.

Example:
```text
$ curl -d '' http://169.254.169.254/refresh
success
```

A typical HTTP call chain to force refresh a set of credentials requiring MFA will look similar to:

```text
$ curl -d '' http://169.254.169.254/refresh
success

# This call to /profile is optional and only demonstrates the data returned from a call where new MFA is required
$ curl -d my-profile http://169.254.169.254/profile
MFA code required

$ curl -d 123456 http://169.254.169.254/mfa
2019-01-02 12:34:56 -0500 CDT

$ curl -d my-profile http://169.254.169.254/profile
2019-01-02 12:34:56 -0500 CDT
```