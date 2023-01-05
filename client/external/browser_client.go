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
	"log"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
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

var done sync.WaitGroup

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
	var browserExec string
	c.Logger.Debugf("Starting a browser to authenticate..")
	network.Enable()
	fetch.Enable()
	dir, err := homedir.Dir()
	if err != nil {
		log.Println(err)
	}
	dir += `/.aws/.browser`
	// Remove the default option for headless
	opts := chromedp.DefaultExecAllocatorOptions[0:1]
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
		chromedp.Flag(`profile-directory`, `aws-runas`),
		chromedp.WindowSize(400, 700),
		chromedp.NoDefaultBrowserCheck,
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	// also set up a custom error logger
	taskCtx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(c.Logger.Errorf))
	defer cancel()
	// Waitgroup to wait on the browser SAMLResponse
	done.Add(1)
	// Setup a listener to be called for each browser event in a separate go routine
	chromedp.ListenTarget(taskCtx, c.targetListener)
	// ensure that the browser process is started and navigate to auth page
	if err = chromedp.Run(taskCtx,
		chromedp.Navigate(c.authUrl.String()),
	); err != nil {
		done.Done()
		_ := chromedp.Cancel(taskCtx)
		return err
	}
	// Wait for SAMLResponse from Browser
	done.Wait()
	_ := chromedp.Cancel(taskCtx)
	c.Logger.Debugf("Authentication Finished.")
	return nil
}

// Listen to the browser events for the send to AWS with SAMLResponse
// get it and stuff it into our Clients SAML assertion.
func (c *browserClient) targetListener(ev interface{}) {
	switch ev := ev.(type) {  //nolint:gocritic
	case *network.EventRequestWillBeSent:
		if ev.Request.URL == `https://signin.aws.amazon.com/saml` {
			escsaml := strings.Replace(ev.Request.PostData, `SAMLResponse=`, ``, 1)
			saml, err := url.QueryUnescape(escsaml)
			if err != nil {
				time.Sleep(time.Second * 1)
				c.Logger.Debugf("%s", err)
			}
			samlassert := credentials.SamlAssertion(saml)
			c.saml = &samlassert
			done.Done()
		}
	}
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
