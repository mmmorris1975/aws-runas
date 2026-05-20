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
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	cdpbrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	cdpstorage "github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"
	"github.com/mitchellh/go-homedir"

	"github.com/mmmorris1975/aws-runas/credentials"
	"github.com/mmmorris1975/aws-runas/identity"
)

const (
	MacOSEdge          = `/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge`
	WinOSEdge          = `C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe`
	browserAuthTimeout = 5 * time.Minute
)

type browserClient struct {
	*baseClient
	done chan struct{}
}

// NewBrowserClient provides a Saml and Web client suitable for testing code outside of this package.
// It returns zero-value objects, and never errors.
func NewBrowserClient(url string) (*browserClient, error) {
	bc, err := newBaseClient(url)
	if err != nil {
		return nil, err
	}
	return &browserClient{baseClient: bc}, nil
}

func (c *browserClient) Identity() (*identity.Identity, error) {
	if c.baseClient == nil {
		return nil, errNilClient
	}
	return c.identity(browserProvider), nil
}

// Authenticate calls AuthenticateWithContext using a background context.
func (c *browserClient) Authenticate() error {
	return c.AuthenticateWithContext(context.Background())
}

// AuthenticateWithContext uses Chromedp to open a browser for the authentication process.
func (c *browserClient) AuthenticateWithContext(context.Context) error {
	if c.baseClient == nil || c.Logger == nil {
		return errNilClient
	}

	dir, err := homedir.Dir()
	if err != nil {
		return fmt.Errorf("resolve home dir: %w", err)
	}
	profileDir := filepath.Join(dir, ".aws", ".browser")

	var execPath string
	switch c.AuthBrowser {
	case "msedge":
		if runtime.GOOS == "windows" {
			execPath = WinOSEdge
		} else if runtime.GOOS == "darwin" {
			execPath = MacOSEdge
		} else {
			c.Logger.Infof("msedge not supported on %s, using chrome", runtime.GOOS)
		}
	case "chrome", "":
	default:
		c.Logger.Infof("browser %s not supported, using chrome if available.", c.AuthBrowser)
	}

	c.Logger.Debugf("Starting a browser to authenticate...")

	taskCtx, cancel, err := c.startBrowser(profileDir, execPath)
	if err != nil {
		return err
	}

	c.done = make(chan struct{}, 1)
	var once sync.Once
	chromedp.ListenTarget(taskCtx, func(ev any) {
		c.targetListener(ev, &once)
	})

	c.Logger.Debugf("Auth Nav: %s", c.authUrl.String())
	if err := chromedp.Run(taskCtx,
		network.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, _, _, _, err := page.Navigate(c.authUrl.String()).Do(ctx)
			return err
		}),
	); err != nil {
		cancel()
		return err
	}

	var authErr error
	select {
	case <-c.done:
	case <-taskCtx.Done():
		authErr = fmt.Errorf("browser closed before authentication completed")
	case <-time.After(browserAuthTimeout):
		authErr = fmt.Errorf("timed out waiting for SAML response (%s)", browserAuthTimeout)
	}

	if authErr == nil {
		persistSessionCookies(taskCtx)
	}
	cancel()

	if authErr != nil {
		return authErr
	}

	c.Logger.Debugf("Authentication Finished.")
	return nil
}

// startBrowser cleans up any stale Chrome state, spawns Chrome via chromedp's ExecAllocator,
// and returns a task context. Chrome is closed when cancel is called.
func (c *browserClient) startBrowser(profileDir, execPath string) (context.Context, context.CancelFunc, error) {
	if err := os.MkdirAll(profileDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("create browser profile dir: %w", err)
	}

	killOrphanedChrome(profileDir)
	for _, name := range []string{"SingletonLock", "SingletonSocket", "SingletonCookie", "DevToolsActivePort"} {
		_ = os.Remove(filepath.Join(profileDir, name))
	}
	_ = os.RemoveAll(filepath.Join(profileDir, "aws-runas", "Sessions"))

	opts := []chromedp.ExecAllocatorOption{chromedp.DefaultExecAllocatorOptions[0]}
	if execPath != "" {
		opts = append(opts, chromedp.ExecPath(execPath))
	}
	opts = append(opts,
		chromedp.UserDataDir(profileDir),
		chromedp.Flag("profile-directory", "aws-runas"),
		chromedp.Flag("disable-session-crashed-bubble", true),
		chromedp.Flag("hide-crash-restore-bubble", true),
		chromedp.Flag("noerrdialogs", true),
		chromedp.WindowSize(400, 700),
		chromedp.NoDefaultBrowserCheck,
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	taskCtx, taskCancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(c.Logger.Errorf))
	cancel := func() {
		pid := chromePIDFromLock(profileDir)
		_ = chromedp.Run(taskCtx, chromedp.ActionFunc(func(ctx context.Context) error {
			return cdpbrowser.Close().Do(ctx)
		}))
		taskCancel()
		allocCancel()
		waitForProcessExit(pid, 3*time.Second)
	}
	return taskCtx, cancel, nil
}

// persistSessionCookies converts session cookies (Expires == -1) to persistent cookies with a 24-hour
// expiry so they survive the graceful browser shutdown. Without this, Chrome's normal exit clears
// all session cookies, forcing MFA and KMSI prompts on every invocation.
func persistSessionCookies(ctx context.Context) {
	var all []*network.Cookie
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		all, err = cdpstorage.GetCookies().Do(ctx)
		return err
	})); err != nil || len(all) == 0 {
		return
	}
	expires := cdp.TimeSinceEpoch(time.Now().Add(24 * time.Hour))
	_ = chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		for _, c := range all {
			if c.Expires > 0 {
				continue
			}
			if c.Name == "" {
				continue
			}
			params := network.SetCookie(c.Name, c.Value).
				WithDomain(c.Domain).
				WithPath(c.Path).
				WithSecure(c.Secure).
				WithHTTPOnly(c.HTTPOnly).
				WithSameSite(c.SameSite).
				WithExpires(&expires).
				WithPriority(c.Priority)
			_ = params.Do(ctx)
		}
		return nil
	}))
}

// killOrphanedChrome reads Chrome's SingletonLock symlink to find a stale process, terminates it,
// and waits for it to fully exit before returning. No-op on Windows.
func killOrphanedChrome(profileDir string) {
	if runtime.GOOS == "windows" {
		return
	}
	target, err := os.Readlink(filepath.Join(profileDir, "SingletonLock"))
	if err != nil {
		return
	}
	parts := strings.Split(target, "-")
	if len(parts) < 2 {
		return
	}
	pid, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil || pid <= 0 {
		return
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "args=").Output()
	if err != nil {
		return
	}
	args := strings.TrimSpace(string(out))
	if !strings.Contains(strings.ToLower(args), "chrome") || !strings.Contains(args, profileDir) {
		return
	}
	_ = exec.Command("kill", strconv.Itoa(pid)).Run()

	// Poll until the process is gone (up to 3s) so its file locks are fully released
	// before the new ExecAllocator tries to use the same profile directory.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		proc, err := os.FindProcess(pid)
		if err != nil {
			break
		}
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func chromePIDFromLock(profileDir string) int {
	target, err := os.Readlink(filepath.Join(profileDir, "SingletonLock"))
	if err != nil {
		return 0
	}
	parts := strings.Split(target, "-")
	if len(parts) < 2 {
		return 0
	}
	pid, _ := strconv.Atoi(parts[len(parts)-1])
	return pid
}

func waitForProcessExit(pid int, max time.Duration) {
	if pid <= 0 || runtime.GOOS == "windows" {
		return
	}
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		proc, err := os.FindProcess(pid)
		if err != nil {
			return
		}
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// targetListener listens for the SAML POST to AWS and extracts the SAMLResponse.
func (c *browserClient) targetListener(ev any, once *sync.Once) {
	switch ev := ev.(type) { //nolint:gocritic
	case *network.EventRequestWillBeSent:
		if ev.Request.URL == `https://signin.aws.amazon.com/saml` {
			for i, entry := range ev.Request.PostDataEntries {
				decoded, _ := base64.StdEncoding.DecodeString(entry.Bytes)
				c.Logger.Debugf("%d - %s\n", i, string(decoded))
				qs, err := url.ParseQuery(string(decoded))
				if err != nil {
					c.Logger.Errorf("Error parsing SAMLResponse: %v", err)
					continue
				}
				saml := qs.Get("SAMLResponse")
				if saml == "" {
					continue
				}
				samlassert := credentials.SamlAssertion(saml)
				c.saml = &samlassert
				once.Do(func() {
					c.done <- struct{}{}
				})
				return
			}
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
