---
title: Program Usage
---

How to use aws-runas to perform various functions

#### Program Options
```text
NAME:
   aws-runas - Create an environment for interacting with the AWS API using an assumed role

USAGE:
   aws-runas [global options] [subcommand] profile [arguments...]

VERSION:
   3.0-alpha

COMMANDS:
   list, ls              Shows IAM roles or MFA device configuration
   serve, srv            Serve credentials from a listening HTTP service
   ssm                   Helpful shortcuts for working with SSM sessions
   password, passwd, pw  Set or update the stored password for an external identity provider
   diagnose, diag        run diagnostics to gather information to aid in troubleshooting
   help, h               Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --duration value, -d value       duration of the retrieved session token (default: 12 hours) [$SESSION_TOKEN_DURATION]
   --role-duration value, -a value  duration of the assume role credentials (default: 1 hours) [$CREDENTIALS_DURATION]
   --otp value, -o value            MFA token code [$MFA_CODE]
   --mfa-serial value, -M value     serial number (or AWS ARN) of MFA device needed to perform Assume Role operation [$MFA_SERIAL]
   --external-id value, -X value    external ID to use with Assume Role [$EXTERNAL_ID]
   --jump-role value, -J value      ARN of the 'jump role' to use with SAML or Web Identity integration [$JUMP_ROLE_ARN]
   --saml-url value, -S value       URL of the SAML authentication endpoint [$SAML_AUTH_URL]
   --web-url value, -W value        URL of the Web Identity (OIDC) authentication endpoint [$WEB_AUTH_URL]
   --web-redirect value, -T value   Web Identity (OIDC) redirect URI [$WEB_REDIRECT_URI]
   --web-client value, -C value     Web Identity (OIDC) client ID [$WEB_CLIENT_ID]
   --username value, -U value       username for SAML or Web Identity (OIDC) authentication [$RUNAS_USERNAME, $SAML_USERNAME, $WEB_USERNAME]
   --password value, -P value       password for SAML or Web Identity (OIDC) authentication [$RUNAS_PASSWORD, $SAML_PASSWORD, $WEB_PASSWORD]
   --provider value, -R value       name of the SAML or Web Identity (OIDC) provider to use [$RUNAS_PROVIDER, $SAML_PROVIDER, $WEB_PROVIDER]
   --env, -E                        pass credentials to program as environment variables (default: false) [$RUNAS_ENV_CREDENTIALS]
   --output value, -O value         credential output format, valid values: env or json (default: "env") [$RUNAS_OUTPUT_FORMAT]
   --session, -s                    use session token credentials instead of role credentials (default: false) [$RUNAS_SESSION_CREDENTIALS]
   --refresh, -r                    force a refresh of the cached credentials (default: false)
   --expiration, -e                 show credential expiration time (default: false)
   --whoami, -w                     print the AWS identity information for the provided profile credentials (default: false)
   --list-mfa, -m                   list the ARN of the MFA device associated with your IAM account (default: false)
   --list-roles, -l                 list role ARNs you are able to assume (default: false)
   --update, -u                     check for updates to aws-runas-v3 (default: false)
   --diagnose, -D                   run diagnostics to gather information to aid in troubleshooting (default: false)
   --verbose value, -v value        output debug logging, use twice for AWS call tracing (default: standard logging)
   --help, -h                       show help (default: false)
   --version, -V                    print the version (default: false)
```

### Environment Variables

### Diagnostics

### Listing Roles

### Listing MFA Devices

### Show Credential Expiration

### Show Identity Information