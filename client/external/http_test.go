package external

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func Test_newHttpRequest(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		_, err := newHttpRequest(context.Background(), http.MethodGet, "http://localhost")
		if err != nil {
			t.Error(err)
			return
		}
	})

	//nolint:staticcheck // I know all about not passing nil context
	t.Run("nil context", func(t *testing.T) {
		_, err := newHttpRequest(nil, http.MethodGet, "http://localhost")
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("bad method", func(t *testing.T) {
		_, err := newHttpRequest(context.Background(), "| |", "http://localhost")
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})

	t.Run("bad url", func(t *testing.T) {
		_, err := newHttpRequest(context.Background(), http.MethodGet, ":localhost")
		if err == nil {
			t.Error("did not receive expected error")
			return
		}
	})
}

func Test_withContentType(t *testing.T) {
	r, _ := newHttpRequest(context.Background(), http.MethodPost, "http://localhost")

	t.Run("default", func(t *testing.T) {
		if len(r.Header.Get("Content-Type")) > 0 {
			t.Error("unexpected content-type")
		}
	})

	t.Run("with value", func(t *testing.T) {
		r.withContentType(contentTypeJson)
		if r.Header.Get("Content-Type") != contentTypeJson {
			t.Error("unexpected content-type")
		}
	})
}

func Test_withValue(t *testing.T) {
	v := url.Values{}
	v.Set("a", "1")

	r, _ := newHttpRequest(context.Background(), http.MethodPost, "http://localhost")
	r.withValues(v)

	if r.Header.Get("Content-Type") != contentTypeForm {
		t.Error("invalid content-type")
	}

	if r.Body == nil {
		t.Error("invalid body")
	}

	if r.ContentLength < 1 {
		t.Error("invalid content length")
	}
}

func Test_withBody(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		r, _ := newHttpRequest(context.Background(), http.MethodPost, "http://localhost")
		r.withBody(nil)

		if _, ok := r.Body.(io.ReadCloser); !ok || r.ContentLength > -1 {
			t.Error("invalid body")
		}
	})

	t.Run("bytes.Buffer", func(t *testing.T) {
		b := bytes.NewBuffer([]byte("data"))

		r, _ := newHttpRequest(context.Background(), http.MethodPost, "http://localhost")
		r.withBody(b)

		if _, ok := r.Body.(io.ReadCloser); !ok || r.ContentLength != int64(b.Len()) {
			t.Error("invalid body")
		}
	})

	t.Run("bytes.Reader", func(t *testing.T) {
		b := bytes.NewReader([]byte("data"))

		r, _ := newHttpRequest(context.Background(), http.MethodPost, "http://localhost")
		r.withBody(b)

		if _, ok := r.Body.(io.ReadCloser); !ok || r.ContentLength != int64(b.Len()) {
			t.Error("invalid body")
		}
	})

	t.Run("strings.Reader", func(t *testing.T) {
		b := strings.NewReader("data")

		r, _ := newHttpRequest(context.Background(), http.MethodPost, "http://localhost")
		r.withBody(b)

		if _, ok := r.Body.(io.ReadCloser); !ok || r.ContentLength != int64(b.Len()) {
			t.Error("invalid body")
		}
	})

	t.Run("io.ReadCloser", func(t *testing.T) {
		b := io.NopCloser(strings.NewReader("data"))

		r, _ := newHttpRequest(context.Background(), http.MethodPost, "http://localhost")
		r.withBody(b)

		if _, ok := r.Body.(io.ReadCloser); !ok || r.ContentLength > -1 {
			t.Error("invalid body")
		}
	})

	t.Run("io.Reader", func(t *testing.T) {
		b := io.LimitReader(strings.NewReader("data"), 20)

		r, _ := newHttpRequest(context.Background(), http.MethodPost, "http://localhost")
		r.withBody(b)

		if _, ok := r.Body.(io.ReadCloser); !ok || r.ContentLength > -1 {
			t.Error("invalid body")
		}
	})
}
