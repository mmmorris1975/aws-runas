/*
 * Copyright (c) 2021 Michael Morris. All Rights Reserved.
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
	"bytes"
	"context"
	"fmt"
	"io"
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
		rc = io.NopCloser(bytes.NewReader(data))
	case *bytes.Reader:
		r.ContentLength = int64(t.Len())
		rc = io.NopCloser(t)
	case *strings.Reader:
		r.ContentLength = int64(t.Len())
		rc = io.NopCloser(t)
	case io.ReadCloser:
		rc = t
	default:
		rc = io.NopCloser(t)
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
