package main

import (
	"fmt"
	"net/http"
	"strings"
)

var (
	// Version is the program version, set at build-time based on git tags/commit hash (see Makefile)
	Version string
	ghUrl   = "https://github.com/mmmorris1975/aws-runas/releases/latest"
)

func versionCheck(ver string) error {
	http.DefaultClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Don't follow redirects, just return 1st response
		return http.ErrUseLastResponse
	}

	res, err := http.Head(ghUrl)
	if err != nil {
		return err
	}

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
