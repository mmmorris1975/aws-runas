---
layout: page
title: SAML Client Configuration Guide
---
# SAML Client Configuration
At this time, aws-runas works with Forgerock, Keycloak, Okta, and OneLogin Identity Providers who have configured SSO
integration with AWS via SAML 2.0.  The sections below will describe the specific configuration needed to work with each
supported provider.  Many of the details specific to your instance of the identity provider (like the URL) will need to
be shared to you by your identity platform adminstrators.

In all of the examples below, the `saml_provider` configuration attribute is optional, and can be used to bypass the client
auto-detection logic.

## Forgerock
Forgerock is a self-hosted identity management platform, so the specific details may vary based on the configuration of
your specific implementation of the Forgerock product.  The aws-runas SAML client auto-discovery logic performs an HTTP
HEAD against the URL and looks for either `X-OpenAM-` or `MFA-FR-Token` in the `Access-Control-Allow-Headers` response
header.

Example Forgerock info in the .aws/config file:
```text
saml_auth_url = https://my-forgerock-hostname.com/auth/json/realms/__the-realm__/authenticate
saml_provider = forgerock
```

## Keycloak
Keycloak is a self-hosted identity management platform, so the specific details may vary based on the configuration of
your specific implementation of the Keycloak product.  The aws-runas SAML client auto-discovery logic performs an HTTP
HEAD against the URL and looks for a cookie called `KC_RESTART` in the response.

Example Keycloak info in the .aws/config file:
```text
saml_auth_url = https://my-keycloak-hostname.com/auth/realms/__the-realm__/protocol/saml/clients/__client_name__
saml_provider = keycloak
```

## Okta
Okta is a commercial identity management service which provides the necessary infrastructure and services to integrate
with numerous 3rd party applications.  The 'App Embed Link' for the AWS Okta application is used for the URL in the
configuration.  The aws-runas SAML client auto-discovery logic looks for `.okta` in the hostname portion of the URL.

Example Okta info in the .aws/config file:
```text
saml_auth_url = https://my-okta-hostname.com/home/amazon_aws/__okta_app_id__/__other_part__
saml_provider = okta
```

## OneLogin
OneLogin is a commercial identity management service which provides the necessary infrastructure and services to integrate
with numerous 3rd party applications. The 'SAML 2.0 Endpoint' for the AWS OneLogin application is used for the URL in the
configuration. The aws-runas SAML client auto-discovery logic looks for `.onelogin.com` in the hostname portion of the URL.

The OneLogin platform requires the use of authentication for interacting with any portion of their API (even for
authenticating public/untrusted apps). This necessitates your OneLogin admins create a set of API credentials which can
be shared as they see fit to allow aws-runas the ability to communicate with the OneLogin API.  The OneLogin API
credentials will be a Client ID and Client Secret, which are added as the query string parameter `token` to the OneLogin
URL in the .aws/config file.  This is an aws-runas specific configuration, and not supported as part of interacting with
the OneLogin API.  The format of the token parameter is the base64 encoding of the Client ID and Client Secret values
joined with a `:` between them. If you have access to a MacOS or Linux system, the following command can be used to
generate the necessary value:

```shell script
echo -n 'client_id:client_secret' | base64
```

Substituting client_id and client_secret with your actual values, of course. On some Linux systems you may need to add
the `-w0` flag to the base64 command to disable text wrapping.

Example Okta info in the .aws/config file:
```text
saml_auth_url = https://my-onelogin-hostname.com/trust/saml2/http-post/sso/__app_id__?token=Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=
saml_provider = onelogin
```