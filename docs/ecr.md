---
title: ECR Authentication Support
---

aws-runas provides built-in support for authenticating to ECR for managing docker image repositories.  This is provided
as a shortcut to the previous workflow of using aws-runas to obtain credentials for a profile and then using a command
pipeline to execute `docker login` with the credentials.

### Prerequisites

The `docker` command must be available on the system, and it must be accessible via the PATH environment variable.

### Usage

Versions of aws-runas prior to 3.1.0 required extra steps (and depended on external tools like awscli) to authenticate
with ECR, similar to:
```shell
aws-runas my_profile aws ecr get-login-password | docker login --username AWS --password-stdin aws_account_id.dkr.ecr.region.amazonaws.com
```

With the ECR authentication feature, everything is handled internally to aws-runas, from getting the ECR credentials to
executing `docker login` for authenticate with the endpoint.  The command is now simplified to:
```shell
aws-runas ecr login my_profile [ECR endpoint ...]
```

In the above example, the ECR endpoint parameter(s) at the end of the command is an optional space-separated list of ECR
endpoints to authenticate with.  If no ECR endpoint is explicitly provided, the ECR registry in the account and region
associated with the profile is contacted.  The ECR endpoints can also be either the full name of the ECR endpoint, or
just the account number of the AWS account which manages that ECR.  If only an account number is provided, the registry
in the region associated with the profile will be contacted.

### Examples

#### No explicit endpoint used
Contact the ECR endpoint in the account and region associated with the specified profile
```shell
aws-runas ecr login my_profile
```

#### Account number only endpoint
Contact the ECR endpoint in the specified AWS account number using the region configured for the profile
```shell
aws-runas ecr login my_profile 012345678901
```

#### Full ECR endpoint name
Contact the ECR endpoint directly
```shell
aws-runas ecr login my_profile 012345678901.dkr.ecr.us-east-2.amazonaws.com
```

#### Multiple ECR registries
Multiple ECR registries can be specified, and each will be resolved (if necessary) and authenticated
```shell
aws-runas ecr login my_profile 012345678901.dkr.ecr.us-west-2.amazonaws.com 987654321012
```