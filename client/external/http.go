package external

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type httpRequest struct {
	*http.Request
}

func newHttpRequest(ctx context.Context, method string, url string) (*httpRequest, error) {
	// errors will come from nil ctx, invalid method, bad url
	r, err := http.NewRequestWithContext(ctx, method, url, http.NoBody)
	return &httpRequest{Request: r}, err
}

func (r *httpRequest) withContentType(contentType string) *httpRequest {
	r.Header.Set("Content-Type", contentType)
	return r
}

// this will not error or panic with a nil argument, so expect an error or panic down the line.
func (r *httpRequest) withBody(body io.Reader) *httpRequest {
	var rc io.ReadCloser
	r.ContentLength = -1

	switch t := body.(type) {
	case *bytes.Buffer:
		data := t.Bytes()
		r.ContentLength = int64(len(data))
		rc = ioutil.NopCloser(bytes.NewReader(data))
	case *bytes.Reader:
		r.ContentLength = int64(t.Len())
		rc = ioutil.NopCloser(t)
	case *strings.Reader:
		r.ContentLength = int64(t.Len())
		rc = ioutil.NopCloser(t)
	case io.ReadCloser:
		rc = t.(io.ReadCloser)
	default:
		rc = ioutil.NopCloser(t)
	}

	r.Body = rc
	return r
}

func (r *httpRequest) withValues(v url.Values) *httpRequest {
	r.withContentType(contentTypeForm)
	return r.withBody(strings.NewReader(v.Encode()))
}

func checkResponseError(r *http.Response, err error) (*http.Response, error) {
	if err != nil {
		return nil, err
	} else if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %s (%d)", r.Status, r.StatusCode)
	}
	return r, err
}
