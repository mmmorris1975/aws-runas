package templates

const IndexHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1,shrink-to-fit=no"/>
    <title>aws-runas Metadata Credential Service</title>
    <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
    <link rel="stylesheet" href="site.css">
</head>
<body>
<main class="w3-container w3-margin-top w3-margin-bottom w3-white w3-round-xlarge">
	<div id="alerts" class="w3-panel w3-display-container">
	  <span id="alert-close" class="w3-button w3-display-topright" title="Close">&times;</span>
	  <h3 id="alert-type"></h3>
	  <p id="alert-text"></p>
	</div>
    <h3 class="w3-center">AWS Metadata Credential Service</h3>
    <form id="role-form" name="role-form">
        <div class="w3-center" style="padding-bottom: 0.5em">
            <label for="roles" class="short-label" title="Profile name of the role to use">Role</label>
            <select id="roles" name="roles" class="w3-input w3-border w3-round" style="width: 50%"
                    title="Profile name of the role to use">
                <option value="">-- Select Role --</option>
            </select>
<!--
            <button type="button" id="refresh" name="refresh"
                    class="w3-button w3-round-large w3-red w3-border w3-border-red w3-hover-white w3-margin-left"
                    title="Force a refresh of the credentials, may require re-authentication or re-entering MFA code">
                Refresh Now
            </button>
-->
        </div>
        <button type="button"
                class="w3-button w3-padding-small w3-block w3-left-align w3-white w3-hover-white accordion"
                title="Advanced configuration options">
            <i>Advanced</i>
        </button>
        <div id="advanced-form">
            <label for="adv-type" title="Type of role to configure">Type</label>
            <select id="adv-type" name="adv-type" class="w3-input w3-border w3-round" title="Type of role to configure">
                <option value="iam">IAM</option>
                <option value="saml">SAML</option>
                <option value="oidc">Web Identity (OIDC)</option>
            </select><br>
            <label for="role-arn" title="ARN of the target role">Role ARN</label>
            <input type="text" id="role-arn" name="role-arn" class="w3-input w3-border w3-round"
                   title="ARN of the target role" placeholder="arn:aws:iam::0123456789012:role/Dev"><br>
            <div id="source-profile-block">
                <label for="source-profile"
                       title="Optional source profile with credentials and configuration for IAM role">
                    Source Profile
                </label>
                <select id="source-profile" name="source-profile" class="w3-input w3-border w3-round"
                        title="Optional source profile with credentials and configuration for IAM role">
                    <option value="default">default</option>
                </select>
            </div>
            <div id="external-id-block">
                <label for="external-id" title="Optional External ID for IAM role">External ID</label>
                <input type="text" id="external-id" name="external-id" class="w3-input w3-border w3-round"
                       title="Optional External ID for IAM role">
            </div>
            <div id="auth-url-block">
                <label for="auth-url" title="URL of the external authentication service">Auth URL</label>
                <input type="url" id="auth-url" name="auth-url" class="w3-input w3-border w3-round"
                       title="URL of the external authentication service">
            </div>
            <div id="username-block">
                <label for="username" title="Username used with external authentication service">Username</label>
                <input type="text" id="username" name="username" class="w3-input w3-border w3-round"
                       title="Username used with external authentication service">
            </div>
            <div id="password-block">
                <label for="password" title="Password used with external authentication service">Password</label>
                <input type="password" id="password" name="password" class="w3-input w3-border w3-round"
                       title="Password used with external authentication service">
            </div>
            <div id="jump-role-block">
                <label for="jump-role" title="Optional ARN of role to assume before using target role">Jump
                    Role</label>
                <input type="text" id="jump-role" name="jump-role" class="w3-input w3-border w3-round"
                       title="Optional ARN of role to assume before using target role"
                       placeholder="arn:aws:iam::0987654321098:role/Jump"><br>
            </div>
            <div id="client-id-block">
                <label for="client-id" title="OIDC client ID required for Web Identity roles">Client ID</label>
                <input type="text" id="client-id" name="client-id" class="w3-input w3-border w3-round"
                       title="OIDC client ID required for Web Identity roles">
            </div>
            <div id="redirect-uri-block">
                <label for="redirect-uri" title="OIDC redirect URI required for Web Identity roles">Redirect URI</label>
                <input type="text" id="redirect-uri" name="redirect-uri" class="w3-input w3-border w3-round"
                       title="OIDC redirect URI required for Web Identity roles">
            </div>
            <span class="w3-left w3-margin-top w3-margin-bottom">
            <button type="button" id="save-as"
                    class="w3-button w3-round-large w3-blue w3-border w3-border-blue w3-hover-white w3-margin-right"
                    title="Save configuration to new profile">
                Save As ...
            </button>
            </span>
            <span class="w3-right w3-margin-top w3-margin-bottom">
            <button type="button" id="reset"
                    class="w3-button w3-round-large w3-red w3-border w3-border-red w3-hover-white w3-margin-left"
                    title="Reset current configuration">
                Clear
            </button>
            <button type="submit" id="submit"
                    class="w3-button w3-round-large w3-green w3-border w3-border-green w3-hover-white w3-margin-left"
                    title="Apply advanced configuration">
                Update
            </button>
            </span>
        </div>
    </form>
</main>
<div id="mfa-modal" class="w3-modal">
    <div id="mfa-prompt" class="w3-card-4 w3-padding w3-white w3-modal-content">
        <span id="mfa-message" class="w3-center w3-text-red"></span>
        <span id="mfa-close" class="w3-button w3-hover-red w3-display-topright" title="Close">&times;</span>
        <br>
        <form id="mfa-form" method="post">
            <fieldset>
                <legend>Enter MFA Code</legend>
                <label for="mfa" style="width: auto; margin-right: 1em;"><b>MFA Code</b></label>
                <input id="mfa" name="mfa" type="text" size="8" required class="w3-border w3-round">
            </fieldset>
            <button type="submit" class="w3-btn w3-round w3-block w3-margin-top cred-submit">
                Submit
            </button>
        </form>
    </div>
</div>
<div id="cred-modal" class="w3-modal">
    <div id="cred-prompt" class="w3-card-4 w3-padding w3-white w3-modal-content">
        <span id="login-message" class="w3-center w3-text-red"></span>
        <span id="cred-close" class="w3-button w3-hover-red w3-display-topright" title="Close">&times;</span>
        <br>
        <form id="cred-form" method="post">
            <fieldset>
                <legend>Enter Credentials</legend>
                <div class="w3-row w3-margin-bottom">
                    <div class="w3-quarter">
                        <label for="username"><b>Username</b></label>
                    </div>
                    <div class="w3-rest">
                        <input id="username" name="username" type="text" required class="w3-border w3-round cred-input">
                    </div>
                </div>
                <div class="w3-row">
                    <div class="w3-quarter">
                        <label for="password"><b>Password</b></label>
                    </div>
                    <div class="w3-rest">
                        <input id="password" name="password" type="password" required class="w3-border w3-round cred-input">
                    </div>
                </div>
            </fieldset>
            <input id="cred-type" name="cred-type" type="hidden" value="saml">
            <button type="submit" class="w3-btn w3-round w3-block w3-margin-top cred-submit">
                Login
            </button>
        </form>
    </div>
</div>
<div id="profile-modal" class="w3-modal">
    <div id="profile-prompt" class="w3-card-4 w3-padding w3-white w3-modal-content">
        <span id="profile-close" class="w3-button w3-hover-red w3-display-topright" title="Close">&times;</span>
        <br>
        <form id="profile-form" method="post">
            <fieldset>
                <legend>Enter Profile Name</legend>
                <label for="profile-name" style="width: auto; margin-right: 1em;"><b>Name</b></label>
                <input id="profile-name" name="profile-name" type="text" required class="w3-border w3-round">
            </fieldset>
            <button type="submit" class="w3-btn w3-round w3-block w3-margin-top cred-submit">
                Submit
            </button>
        </form>
    </div>
</div>
<script src="site.js"></script>
</body>
</html>
`
