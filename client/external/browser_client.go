/*
 * Copyright (c) 2022 Craig McNiel. All Rights Reserved.
 *
 * Licensed under the MIT license (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * https://github.com/mmmorris1975/aws-runas/blob/master/LICENSE
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under the License.
 */

package external

import (
	"context"
	"fmt"
	"log"
	"runtime"

	"github.com/chromedp/chromedp"
	"github.com/mitchellh/go-homedir"

	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
)

const (
	MacOSEdge = `/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge`
	WinOSEdge = `C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe`
)

type browserClient struct {
	*baseClient
}

// NewbrowserClient provides a Saml and Web client suitable for testing code outside of this package.
// It returns zero-value objects, and never errors.
func NewBrowserClient(url string) (*browserClient, error) {
	bc, err := newBaseClient(url)
	if err != nil {
		return nil, err
	}
	return &browserClient{bc}, nil
}

func (c *browserClient) Identity() (*identity.Identity, error) {
	return c.identity(browserProvider), nil
}

// Authenticate calls AuthenticateWithContext using a background context.
func (c *browserClient) Authenticate() error {
	return c.AuthenticateWithContext(context.Background())
}

// AuthenticateWithContext uses Chromedp to open a browser for the authentication process.
func (c *browserClient) AuthenticateWithContext(context.Context) error {
	c.Logger.Debugf("Starting a browser to authenticate..")
	dir, err := homedir.Dir()
	if err != nil {
		log.Println(err)
	}
	switch runtime.GOOS {
	case `windows`:
		dir += `/AppData/Local/Google/Chrome/User Data/Default`
	case `darwin`:
		dir += `/Library/Application Support/Google/Chrome/Default`
	case `linux`:
		dir += `/.config/google-chrome/default`
	default:
		dir += `/.config/google-chrome/default`
	}
	// Remove the default option for headless
	opts := chromedp.DefaultExecAllocatorOptions[0:1]
	var browserExec string
	var attrs []map[string]string
	c.Logger.Debugf("Browser specified from config [ %s ] (Chrome is default)", c.AuthBrowser)

	switch c.AuthBrowser {
	case "msedge":
		if runtime.GOOS == `windows` {
			browserExec = WinOSEdge
		} else {
			browserExec = MacOSEdge
		}
		opts = append(opts,
			chromedp.ExecPath(browserExec),
		)

	case `chrome`:
		// Chrome is the effective default
	case ``:
		// Unspecified invokes the default of Chrome
	default:
		// Should never get here with validation on the config
		c.Logger.Infof("browser %s not supported using chrome if available.", c.AuthBrowser)
	}

	opts = append(opts,
		chromedp.UserDataDir(dir),
		chromedp.Flag(`shared-files`, true),
		chromedp.Flag(`profile-directory`, `Default`),
		chromedp.WindowSize(400, 700),
		chromedp.NoDefaultBrowserCheck,
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	// also set up a custom error logger
	taskCtx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(c.Logger.Errorf))
	defer cancel()

	// ensure that the browser process is started
	if err = chromedp.Run(taskCtx,
		chromedp.Navigate(c.authUrl.String()),
	); err != nil {
		return err
	}

	// chromedp.ListenTarget(taskCtx, networkEvents)
	err = chromedp.Run(taskCtx,
		chromedp.AttributesAll(`SAMLResponse`, &attrs),
	)
	if err != nil {
		fmt.Println(err)
	}
	samlre := attrs[0][`value`]
	saml := credentials.SamlAssertion(samlre)
	c.saml = &saml

	c.Logger.Debugf("SAMLResponse:\n%s", saml)
	rd, _ := saml.RoleDetails()
	c.Logger.Debugf("SAML Role Details:\n%s", rd)
	_ = chromedp.Cancel(taskCtx)
	c.Logger.Debugf("Authentication Finished.")
	return nil
}

// Roles retrieves the available roles for the user.  Attempting to call this method
// against an Oauth/OIDC client will return an error.
func (c *browserClient) Roles(...string) (*identity.Roles, error) {
	if c.saml == nil || len(*c.saml) < 1 {
		var err error
		c.saml, err = c.SamlAssertion()
		if err != nil {
			return nil, err
		}
	}

	return c.roles()
}

// IdentityToken calls IdentityTokenWithContext using a background context.
func (c *browserClient) IdentityToken() (*credentials.OidcIdentityToken, error) {
	return c.IdentityTokenWithContext(context.Background())
}

// IdentityTokenWithContext returns an empty OidcIdentityToken type.
func (c *browserClient) IdentityTokenWithContext(context.Context) (*credentials.OidcIdentityToken, error) {
	_ = c.Authenticate()
	return new(credentials.OidcIdentityToken), nil
}

// SamlAssertion calls SamlAssertionWithContext using a background context.
func (c *browserClient) SamlAssertion() (*credentials.SamlAssertion, error) {
	return c.SamlAssertionWithContext(context.Background())
}

// SamlAssertionWithContext returns a "valid enough" SamlAssertion type.
func (c *browserClient) SamlAssertionWithContext(ctx context.Context) (*credentials.SamlAssertion, error) {
	if c.baseClient == nil {
		c.baseClient = new(baseClient)
	}

	err := c.AuthenticateWithContext(ctx)
	if err != nil {
		return nil, err
	}

	return c.saml, nil
}
