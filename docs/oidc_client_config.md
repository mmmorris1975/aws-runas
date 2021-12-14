---
title: OIDC Client Configuration Guide
---
aws-runas works with many identity providers which offer SSO integration with AWS via OIDC.  The sections below will
describe the specific configuration needed to work with each supported provider.  Many details specific to your instance
of the identity provider (like the URL, client ID, and callback URI) must be shared with you by your identity platform
administrators.

If a particular OIDC identity provider is not listed here, and you would like to see it added to aws-runas, create a new
[github issue]({{ site.github.issues_url }}) and let us know.

In all the examples below, the `web_identity_provider` configuration attribute is optional, and can be used to bypass the
client auto-detection logic.

### Forgerock
Forgerock is a self-hosted identity management platform, so the details may vary based on the configuration of your
specific implementation of the Forgerock product.  The aws-runas OIDC client auto-discovery logic performs an HTTP
HEAD against the URL and looks for either `X-OpenAM-` or `MFA-FR-Token` in the `Access-Control-Allow-Headers` response
header.

Example Forgerock info in the .aws/config file:
```text
web_identity_auth_url = https://my-forgerock-hostname.com/auth/oauth2/realms/__the-realm__
web_identity_client_id = myClientId
web_identity_callback_uri = app:/callback
web_identity_provider = forgerock
```

### Keycloak
Keycloak is a self-hosted identity management platform, so the details may vary based on the configuration of your
specific implementation of the Keycloak product.  The aws-runas OIDC client auto-discovery logic performs an HTTP
HEAD against the URL and looks for a cookie called `KC_RESTART` in the response.

Example Keycloak info in the .aws/config file:
```text
web_identity_auth_url = https://my-keycloak-hostname.com/auth/realms/__the-realm__
web_identity_client_id = myClientId
web_identity_callback_uri = app:/callback
web_identity_provider = keycloak
```

### Microsoft Azure AD
Microsoft Azure AD (AAD) is a commercial identity management service which provides the necessary infrastructure and
services to integrate with numerous 3rd party applications. The `web_identity_auth_url` attribute is common across the
entirety of the AAD tenant. The aws-runas OIDC client auto-discovery logic looks for `.microsoft.com` in the hostname
portion of the URL.

Example Azure AD info in the .aws/config file:
```text
web_identity_auth_url = https://login.microsoftonline.com/__tenant-id__/oauth2/v2.0
web_identity_client_id = myClientId
web_identity_callback_uri = app:/callback
web_identity_provider = azuread
```

The Azure AD client is also configured to allow "guest" account access (which federates the authentication of an Azure
AD principal with an external identity provider).  he big caveat being that the external identity provider must be
supported by aws-runas.  If the AAD username of the guest user matches the username configured in the federated
identity provider, no additional configuration is required.  If the username is different between AAD and the external
identity provider, you can set the `federated_username` attribute in the profile to the value of the username in the
external identity provider.  The following example shows how this might be configured:

```text
web_identity_auth_url = https://login.microsoftonline.com/__tenant-id__/oauth2/v2.0
web_identity_client_id = myClientId
web_identity_callback_uri = app:/callback
web_identity_provider = azuread
web_identity_username = azure-username
federated_username = external-idp-username
```

### Okta
Okta is a commercial identity management service which provides the necessary infrastructure and services to integrate
with numerous 3rd party applications.  The endpoint URL is built by simply adding /oauth2 to the end of your Okta tenant
hostname.  The aws-runas OIDC client auto-discovery logic looks for `.okta.com` in the hostname portion of the URL.

Example Okta info in the .aws/config file:
```text
web_identity_auth_url = https://my-okta-hostname.okta.com/oauth2
web_identity_client_id = myClientId
web_identity_callback_uri = app:/callback
web_identity_provider = okta
```

Additionally, as of the 3.1.3 release, the Okta provider supports integration with Duo MFA using push or code based verification.
No special configuration of aws-runas is required, and you select the MFA method used with Duo using the same `mfa_type`
attribute set in the profile section of the config file as you would with other identity providers.  The only caveat is
that aws-runas assumes Duo MFA is the only MFA factor configured for the user, so if an Okta user enrolls a Duo MFA factor
it will be used regardless of any other MFA factors configured.

### OneLogin
OneLogin is a commercial identity management service which provides the necessary infrastructure and services to integrate
with numerous 3rd party applications. The endpoint URL is built by simply adding /oidc/2 to the end of your OneLogin tenant
hostname. The aws-runas OIDC client auto-discovery logic looks for `.onelogin.com` in the hostname portion of the URL.

The OneLogin platform requires the use of application-level authentication for interacting with any portion of their API
(even for authenticating public/untrusted apps). This necessitates your OneLogin admins create a set of API credentials
which can be shared as they see fit to allow aws-runas the ability to communicate with the OneLogin API.  The OneLogin API
credentials will be a Client ID and Client Secret, which are added as the query string parameter `token` to the OneLogin
URL in the .aws/config file.  This is an aws-runas specific configuration, and not supported as part of interacting with
the OneLogin API.  The format of the token parameter is the base64 encoding of the Client ID and Client Secret values
joined with a `:` between them. If you have access to a MacOS or Linux system, the following command can be used to
generate the necessary value:

```text
echo -n 'client_id:client_secret' | base64
```

Substituting client_id and client_secret with your actual values, of course. On some Linux systems you may need to add
the `-w0` flag to the base64 command to disable text wrapping.

Example OneLogin info in the .aws/config file:
```text
web_identity_auth_url = https://my-onelogin-hostname.com/oidc/2?token=Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=
web_identity_client_id = myClientId
web_identity_callback_uri = app:/callback
web_identity_provider = onelogin
```
The app-id value can be found on the user's application landing page, hovering over the OneLogin AWS Application, and
getting the last element in the URL path.