package main

import (
	"fmt"
	"net/http"
	"strings"
)

const url = "https://github.com/mmmorris1975/aws-runas/releases/latest"

// Version is the program version, set at build-time based on git tags/commit hash (see Makefile)
var Version string

func versionCheck(ver string) error {
	if log != nil {
		log.Debug("Update check")
	}

	r, err := http.NewRequest(http.MethodHead, url, http.NoBody)
	if err != nil {
		return err
	}

	// Get in the weeds so we don't follow redirects
	res, err := http.DefaultTransport.RoundTrip(r)
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
