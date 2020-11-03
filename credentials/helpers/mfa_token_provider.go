package helpers

import (
	"fmt"
	"io"
	"os"
)

type mfaTokenProvider struct {
	input io.Reader
}

// NewMfaTokenProvider returns a MfaInputProvider which will read the MFA token information
// from the provided reader.
func NewMfaTokenProvider(in io.Reader) *mfaTokenProvider {
	return &mfaTokenProvider{input: in}
}

// ReadInput gathers the MFA token value in a way which is compatible with the AWS SDK MFA TokenProvider requirements.
// The prompt will be printed on os.Stderr, and the value will be read from the reader supplied with NewMfaTokenProvider.
func (p *mfaTokenProvider) ReadInput() (string, error) {
	var val string

	fmt.Fprint(os.Stderr, "MFA token code: ")
	_, err := fmt.Fscanln(p.input, &val)
	if err != nil && err != io.EOF {
		return "", err
	}

	return val, nil
}
