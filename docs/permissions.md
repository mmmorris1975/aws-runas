---
layout: page
title: IAM Permissions
---
# AWS IAM Permissions

### Required AWS Permissions

The user's IAM credentials used by this program will need access to call the following AWS APIs to function:

  * AssumeRole (to get the credentials for running under an assumed role)
  * GetSessionToken (to get the session token credentials for running a command or calling AssumeRole)
  * ListMFADevices (get MFA devices for -m option)

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

This <a href="iam_policy.json" target="_blank">sample IAM policy</a> provides you with a starting point for granting users
the ability to use {{ site.title }} effectively. One important omission is the permissions to call the `sts:AssumeRole`
action, since that operation is highly-privileged it should be created as needed outside of this policy; restricting
access to only the necessary IAM roles. Also consider removing the '*' character in the account number field of the
`Resource` ARN values, and replace with your specific AWS account number (The `Resource: *` configuration for the ListMFA
permission is required as part of the AWS API spec, and should not be changed)