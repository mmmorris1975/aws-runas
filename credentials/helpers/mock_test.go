package helpers

import "errors"

type errReader bool

func (e *errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("bad things")
}
