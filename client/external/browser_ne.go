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
	_ "embed"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"

	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
)

type browserNEClient struct {
	*baseClient
}

//go:embed auth_success.html
var htmlsuccess string

//go:embed auth_failed.html
var htmlfail string

// NewbrowserClient provides a Saml and Web client suitable for testing code outside of this package.
// It returns zero-value objects, and never errors.
func NewBrowserNEClient(url string) (*browserNEClient, error) {
	bc, err := newBaseClient(url)
	if err != nil {
		return nil, err
	}
	return &browserNEClient{bc}, nil
}

func (c *browserNEClient) Identity() (*identity.Identity, error) {
	return c.identity(browserNEProvider), nil
}

// Authenticate calls AuthenticateWithContext using a background context.
func (c *browserNEClient) Authenticate() error {
	return c.AuthenticateWithContext(context.Background())
}

// AuthenticateWithContext uses Chromedp to open a browser for the authentication process.
func (c *browserNEClient) AuthenticateWithContext(context.Context) error {
	var err error
	var samlassertion credentials.SamlAssertion
	c.Logger.Debugf("Starting a browser to authenticate with the New Experience flow...")
	// Create a local HTTP listener on a random port.
	httpListener, listenerClose := createHttpListener()
	listenPort := httpListener.Addr().(*net.TCPAddr).Port
	c.Logger.Debugf("Listening on %s", httpListener.Addr().String())
	defer listenerClose()
	// Create the SAML service provider to handle the SAML response.
	// The AcsURL must match the URL the IDP is configured to post the SAML response to.
	// This is typically something like https://mydomain.com/saml/acs
	AcsLocalhost := fmt.Sprintf("http://localhost:%d/", listenPort)
	AcsURL, err := url.Parse(AcsLocalhost)
	if err != nil {
		panic(err) // TODO handle error
	}
	EntityId, err := url.Parse(c.SamlEntityId)
	if err != nil {
		panic(err) // TODO handle error
	}

	// Need to know the SAML2 endpoint for the IDP.
	sed := saml.EntityDescriptor{
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding:  saml.HTTPRedirectBinding,
						Location: c.authUrl.String(),
					},
				},
			},
		},
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		AllowIDPInitiated: true,
		IDPMetadata:       &sed,
		URL:               *AcsURL,
		EntityID:          EntityId.String(),
		ForceAuthn:        false,
		SignRequest:       false,
	})
	// We want the NameID to be an email address.
	samlSP.ServiceProvider.AuthnNameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

	// This creates a url.URL that will start the SAML2 login process
	// Only tested with EntraID so far.
	urlType, err := samlSP.ServiceProvider.MakeRedirectAuthenticationRequest(``)
	requri := urlType.String()
	c.Logger.Debugf("Request URL being made to : %s\n", requri)
	mux := http.NewServeMux()
	shutdown := make(chan bool, 1)

	mux.HandleFunc(`/success`, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(htmlsuccess))
		// Notify the server to shutdown now that we are done.
		shutdown <- true
	})

	mux.HandleFunc(`/fail`, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(htmlfail))
		// Auto close the window
		//  after 5 seconds.
		http.NoBody.Close()
		// Notify the server to shutdown now that we are done.
		shutdown <- true
	})

	mux.HandleFunc("/saml/", func(w http.ResponseWriter, r *http.Request) {
		// Verify and process the SAML response
		encodedXML := r.FormValue(`SAMLResponse`)
		if len(encodedXML) == 0 {
			redir := "http://localhost:" + fmt.Sprintf("%d", listenPort) + "/fail"
			http.Redirect(w, r, redir, http.StatusFound)
			return
		}
		samlassertion = credentials.SamlAssertion(encodedXML)
		c.saml = &samlassertion
		redir := "http://localhost:" + fmt.Sprintf("%d", listenPort) + "/success"
		http.Redirect(w, r, redir, http.StatusFound)
	})

	// Create a local web server to listen for the SAML response.
	httpserver := &http.Server{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		Handler:      mux,
	}

	// Start the server to listen for the SAML response in a separate goroutine.
	go func(httpListener net.Listener) {
		err = httpserver.Serve(httpListener)
		if err != nil && err != http.ErrServerClosed {
			c.Logger.Errorf("Error starting local web server: %v", err)
		}
	}(httpListener)

	c.Logger.Debugf("Request URL being made to : %s", requri)
	err = openBrowser(requri)
	if err != nil {
		c.Logger.Errorf("Error opening browser: %v", err)
		return err
	}
	// Wait here until we get a notification to shutdown the server.
	// This happens when we get the SAML response and process it.
	<-shutdown
	httpserver.Shutdown(context.Background())
	sr, err := c.saml.Decode()
	if err != nil {
		c.Logger.Errorf("Error decoding SAML response: %v", err)
		return err
	}
	c.Username, _ = c.saml.RoleSessionName()
	c.Logger.Debugf("SAML Response Issuer: %s", sr)
	return nil
}

// Roles retrieves the available roles for the user.  Attempting to call this method
// against an Oauth/OIDC client will return an error.
func (c *browserNEClient) Roles(...string) (*identity.Roles, error) {
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
func (c *browserNEClient) IdentityToken() (*credentials.OidcIdentityToken, error) {
	return c.IdentityTokenWithContext(context.Background())
}

// IdentityTokenWithContext returns an empty OidcIdentityToken type.
func (c *browserNEClient) IdentityTokenWithContext(context.Context) (*credentials.OidcIdentityToken, error) {
	_ = c.Authenticate()
	return new(credentials.OidcIdentityToken), nil
}

// SamlAssertion calls SamlAssertionWithContext using a background context.
func (c *browserNEClient) SamlAssertion() (*credentials.SamlAssertion, error) {
	return c.SamlAssertionWithContext(context.Background())
}

// SamlAssertionWithContext returns a "valid enough" SamlAssertion type.
func (c *browserNEClient) SamlAssertionWithContext(ctx context.Context) (*credentials.SamlAssertion, error) {
	if c.baseClient == nil {
		c.baseClient = new(baseClient)
	}
	err := c.AuthenticateWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return c.saml, nil
}

// openBrowser tries to open the URL in a browser.
func openBrowser(url string) error {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin": // macOS
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	return err
}

func createHttpListener() (l net.Listener, close func()) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}
	return l, func() {
		l.Close()
	}
}
