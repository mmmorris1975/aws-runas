---
title: Examples
---

These examples assume you have a valid configuration for the profile you are using.

### Commands

#### Run command using a profile

This is the canonical use-case for aws-runas.  The example below shows how to use aws-runas to execute the `aws s3 ls`
command using credentials for the profile `my-profile`

```shell
aws-runas my-profile aws s3 ls
```

#### Run command using a role ARN

There may be cases where it is inconvenient to create the usual config and credentials files on the system.  To handle
this, aws-runas allows you to directly specify the IAM role ARN on the command-line in lieu of the profile name.

When using the tool in this way, the necessary IAM credentials must be supplied as either environment variables, or
configured in the default section of the ~/.aws/credentials file.

The example below shows how to use aws-runas to execute the `aws s3 ls` command using credentials obtained for the role
`arn:aws:iam::1234567890:role/my-role`. If necessary, the configuration for an MFA device can be provided via the -M
command-line option.

```shell
aws-runas [-M mfa serial] arn:aws:iam::1234567890:role/my-role aws s3 ls
```

### EC2 Metadata

aws-runas provides a feature which emulates the EC2 metadata credential endpoint which is used as part of the default
credential lookup chain. This facility provides a way to vend AWS credentials to programs which are configured to find
credentials at this endpoint.  When configured to use a custom port (via the `-p` command-line option), no additional
privileges are required; otherwise you will need to execute aws-runas using adminstrator/root privileges. For more
information about this service see the
<a href="{{ 'metadata_credentials.html#ec2-metadata-service' | relative_url }}">Metadata Credentials documentation</a>

#### Example

Start the service (running on a non-default port) in one terminal window:

```shell
aws-runas serve ec2 -p 8000 my-profile
```

In another window, configure your environment to use this endpoint and run the command

```shell
export AWS_SHARED_CREDENTIALS_FILE=/dev/null
export AWS_EC2_METADATA_SERVICE_ENDPOINT='http://127.0.0.1:8000/'
aws s3 ls
```

### ECS Metadata

aws-runas provides a feature which emulates the ECS credential endpoint which is used as part of the default credential
lookup chain. This facility provides a way to vend AWS credentials to programs which are configured to find credentials
at this endpoint.  No additional privileges are required to use this endpoint.  For more information about this service
see the <a href="{{ 'metadata_credentials.html#ecs-metadata-service' | relative_url }}">Metadata Credentials documentation</a>

#### Example

Start the service in one terminal window:

```shell
aws-runas serve ecs my-profile
```

In another window, configure your environment to use this endpoint and run the command

```shell
export AWS_SHARED_CREDENTIALS_FILE=/dev/null
export AWS_CONTAINER_CREDENTIALS_FULL_URI='http://127.0.0.1:12319/credentials'
aws s3 ls
```

### Docker

Special consideration is needed when using aws-runas to supply credentials to processes running in docker containers.

#### Injecting Environment Variables

Exposing the AWS credentials as environment variables to the container is one option available. One drawback is this
method is not aware of credential expiration, and has no way to automatically refresh credentials when they expire. So
after some time (between 15 minutes and 12 hours, depending on configuration), the container must be restarted to
run with new credentials. This method is most suitable with short-lived container execution.

##### Example

```shell
aws-runas -E my-profile docker run -e AWS_REGION -e AWS_ACCESS_KEY_ID \
 -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN ...
```

#### Using EC2 Metadata

Running the built-in EC2 Metadata Service of aws-runas is another way to expose AWS credentials to a docker container.
When using this method, it is possible for the credentials to be automatically refreshed when they expire, for as long
as the underlying session is still valid.  The one drawback of this approach is that you must run the service so that
it listens on the 169.254.169.254 address, which requires administrator/root privilege on the system.

When using this method, it is advisable to have separate command-line sessions running, so you can monitor the execution
of aws-runas and the docker container together.

In the first window, run aws-runas as adminstrator/root:

```shell
aws-runas serve ec2 my-profile
```

In the second window, run your docker container as you normally wold:

```shell
docker run ...
```