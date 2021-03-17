---
title: IAM Permissions
---

When using aws-runas with user accounts configured in AWS IAM, the user will need permission to call the following
AWS APIs:

  * AssumeRole (to get the credentials for running under an assumed role)
  * GetSessionToken (to get the session token credentials for running a command or calling AssumeRole)
  * ListMFADevices (get MFA devices via the -m option)

The following API calls are used by the -l option to find assumable roles for the calling user:

  * GetUser
  * ListGroupsForUser
  * GetUserPolicy
  * ListUserPolicies
  * GetGroupPolicy
  * ListGroupPolicies
  * GetPolicy
  * GetPolicyVersion

### Sample IAM Policy

This <a href="{{ 'iam_policy.json' | relative_url }}" target="_blank">sample IAM policy</a> provides you with a starting
point for granting IAM users the ability to use aws-runas effectively. One important omission is the permissions to call
the `sts:AssumeRole` action, since that operation is highly-privileged it should be created as needed outside this policy,
restricting access to only the necessary IAM roles. Also consider removing the '*' character in the account number field
of the `Resource` ARN values, and replace with your specific AWS account number (The `Resource: *` configuration for the
ListMFA permission is required as part of the AWS API spec, and should not be changed)