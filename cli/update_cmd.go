package cli

import (
	"errors"
	"fmt"
	"github.com/urfave/cli/v2"
	"net/http"
	"strings"
	"time"
)

var updateCmd = &cli.Command{
	Name:      "update",
	Usage:     updateFlag.Usage,
	ArgsUsage: " ",
	Hidden:    true,

	Action: func(ctx *cli.Context) error {
		if u, ok := ctx.App.Metadata["url"]; ok {
			ghUrl := fmt.Sprintf("%s/releases/latest", u)
			return versionCheck(ghUrl, ctx.App.Version)
		}
		return errors.New("missing 'url' metadata attribute")
	},
}

func versionCheck(ghUrl, ver string) error {
	http.DefaultClient.Timeout = 5 * time.Second
	http.DefaultClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Don't follow redirects, just return 1st response
		return http.ErrUseLastResponse
	}

	res, err := http.Head(ghUrl) //nolint:gosec
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusFound {
		url, err := res.Location()
		if err != nil {
			return err
		}

		p := strings.Trim(url.Path, `/`)
		f := strings.Split(p, `/`)
		v := f[len(f)-1]

		if v != ver {
			fmt.Printf("New version of aws-runas available: %s\nDownload available at: %s\n", v, url)
			return nil
		}
	}

	return fmt.Errorf("version check failed, bad HTTP Status: %d", res.StatusCode)
}
