---
title: SAML Client Configuration Guide
---
aws-runas works with many identity providers which offer SSO integration with AWS via SAML 2.0.  The sections below will
describe the specific configuration needed to work with each supported provider.  Many details specific to your instance
of the identity provider (like the URL) must be shared with you by your identity platform administrators.

If a particular SAML identity provider is not listed here, and you would like to see it added to aws-runas, create a new
[github issue]({{ site.github.issues_url }}) and let us know.

In all the examples below, the `saml_provider` configuration attribute is optional, and can be used to bypass the client
auto-detection logic.

### Forgerock
Forgerock is a self-hosted identity management platform, so the details may vary based on the configuration of your
specific implementation of the Forgerock product.  The aws-runas SAML client auto-discovery logic performs an HTTP
HEAD against the URL and looks for either `X-OpenAM-` or `MFA-FR-Token` in the `Access-Control-Allow-Headers` response
header.

Example Forgerock info in the .aws/config file:
```text
saml_auth_url = https://my-forgerock-hostname.com/auth/json/realms/__the-realm__/authenticate
saml_provider = forgerock
```

### Keycloak
Keycloak is a self-hosted identity management platform, so the details may vary based on the configuration of your
specific implementation of the Keycloak product.  The aws-runas SAML client auto-discovery logic performs an HTTP
HEAD against the URL and looks for a cookie called `KC_RESTART` in the response.

Example Keycloak info in the .aws/config file:
```text
saml_auth_url = https://my-keycloak-hostname.com/auth/realms/__the-realm__/protocol/saml/clients/__client_name__
saml_provider = keycloak
```

### Microsoft Azure AD
Microsoft Azure AD (AAD) is a commercial identity management service which provides the necessary infrastructure and
services to integrate with numerous 3rd party applications. The 'User Access URL' found in the Properties screen of the
Azure Enterprise Application used for granting access to the AWS role is used for the value of the `saml_auth_url`.
The aws-runas SAML client auto-discovery logic looks for `.microsoft.com` in the hostname portion of the URL.

Example Azure AD info in the .aws/config file:
```text
saml_auth_url = https://myapps.microsoft.com/signin/__app-name__/__app-id__?tenantId=__tenant-id__
saml_provider = azuread
```

The Azure AD client is also configured to allow "guest" account access (which federates the authentication of an Azure
AD principal with an external identity provider).  The big caveat being that the external identity provider must be
supported by aws-runas.  If the AAD username of the guest user matches the username configured in the federated
identity provider, no additional configuration is required.  If the username is different between AAD and the external
identity provider, you can set the `federated_username` attribute in the profile to the value of the username in the
external identity provider.  The following example shows how this might be configured:

```text
saml_auth_url = https://myapps.microsoft.com/signin/__app-name__/__app-id__?tenantId=__tenant-id__
saml_provider = azuread
saml_username = azure-username
federated_username = external-idp-username
```

### Okta
Okta is a commercial identity management service which provides the necessary infrastructure and services to integrate
with numerous 3rd party applications.  The 'App Embed Link' for the AWS Okta application is used for the URL in the
configuration.  The aws-runas SAML client auto-discovery logic looks for `.okta.com` in the hostname portion of the URL.

Example Okta info in the .aws/config file:
```text
saml_auth_url = https://my-okta-hostname.okta.com/home/amazon_aws/__okta_app_id__/__other_part__
saml_provider = okta
```

Additionally, as of the 3.1.3 release, the Okta provider supports integration with Duo MFA using push or code based verification.
No special configuration of aws-runas is required, and you select the MFA method used with Duo using the same `mfa_type`
attribute set in the profile section of the config file as you would with other identity providers.  The only caveat is
that aws-runas assumes Duo MFA is the only MFA factor configured for the user, so if an Okta user enrolls a Duo MFA factor
it will be used regardless of any other MFA factors configured.

### OneLogin
OneLogin is a commercial identity management service which provides the necessary infrastructure and services to integrate
with numerous 3rd party applications. The aws-runas SAML client auto-discovery logic looks for `.onelogin.com` in the
hostname portion of the URL.

The OneLogin platform requires the use of application-level authentication for interacting with any portion of their API
(even for authenticating public/untrusted apps). This requires your OneLogin admins to create a set of API credentials
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
saml_auth_url = https://my-onelogin-hostname.com/trust/saml2/launch/__app_id__?token=Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=
saml_provider = onelogin
```
The app-id value can be found on the user's application landing page, hovering over the OneLogin AWS Application, and
getting the last element in the URL path.

### Browser Provider

The browser provider allows for aws-runas to spawn an external browser connected to aws-runas using the Chrome Developer Protocol CDP.  This allows the user to authenticate through a browser in situations where there isn't a well defined API or where the authentication flow is fluid. AzureAD using policies that leverage tools like inTune, the use of client certificates or other security measures that have these characteristics.

To use the browser provider update the `$HOME/.aws/config` file to include the following configurations.

```text
saml_auth_url = https://myapps.microsoft.com/signin/__app-id__/?tenantId=__tenant-id__
saml_provider=browser
auth_browser=[chrome|msedge] (optional defaults to chrome)
```

This will cause the browser to create a new hidden directory in the `$HOME/.aws/.browser/` that will store the browsers configuration and profile.  Inside of this browser data-directory a profile directory `aws-runas` will be created to store the specific session information for the browser.

Once the browser is started, the user is in control of the authentication session that through the browser.  aws-runas will examine the browser events looking for the return of a `SAMLResponse=xxxx`.   Once this is found aws-runas will capture the SAMLResponse, close the browser session and use it in the same way that other providers do. 

There is no way to use the existing browser SSO information since a normal browser session isn't started with a CDP enabled browser so aws-runas will not be able to monitor events and retrieve the SAML response.

This provider has only been tested with AzureAD but, should work for any other provider.