package helpers

import (
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"os"
)

type userPasswordInputProvider struct {
	input io.Reader
}

// NewUserPasswordInputProvider returns a CredentialInputProvider which will read the username and password
// information from the provided reader.  Username and password values will be read as line-separated values.
func NewUserPasswordInputProvider(in io.Reader) *userPasswordInputProvider {
	return &userPasswordInputProvider{input: in}
}

// ReadInput gathers username and password information.  Either (or both) value can be provided as arguments to
// this method.  Missing values will cause a prompt to be printed to os.Stderr, and the value will be read from
// the reader supplied with NewUserPasswordInputProvider.  If the input reader is determined to be a console/tty,
// a secure password prompt will be used to gather the password input.
func (p *userPasswordInputProvider) ReadInput(user, password string) (string, string, error) {
	var err error

	if len(user) < 1 {
		fmt.Fprint(os.Stderr, "Username: ")
		_, err = fmt.Fscanln(p.input, &user)
		if err != nil && err != io.EOF {
			return "", "", err
		}
	}

	if len(password) < 1 {
		fmt.Fprint(os.Stderr, "Password: ")

		if f, ok := p.input.(*os.File); ok {
			fd := int(f.Fd())
			if terminal.IsTerminal(fd) {
				b, err := terminal.ReadPassword(int(f.Fd()))
				if err != nil && err != io.EOF {
					return "", "", err
				}

				return user, string(b), nil
			}
		}

		_, err = fmt.Fscanln(p.input, &password)
		if err != nil && err != io.EOF {
			return "", "", err
		}
		fmt.Println()
	}

	return user, password, nil
}
