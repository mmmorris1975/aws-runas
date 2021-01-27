package helpers

import (
	"errors"
	"fmt"
	"golang.org/x/term"
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
		_, _ = fmt.Fprint(os.Stderr, "Username: ")
		if err = readInput(p.input, &user); err != nil {
			return "", "", err
		}
	}

	if len(password) < 1 {
		_, _ = fmt.Fprint(os.Stderr, "Password: ")

		if f, ok := p.input.(*os.File); ok {
			password, err = trySecureRead(f)
			if err != nil {
				return "", "", err
			}
		} else if err = readInput(p.input, &password); err != nil {
			return "", "", err
		}
		fmt.Println()
	}

	return user, password, nil
}

func readInput(input io.Reader, dst *string) error {
	_, err := fmt.Fscanln(input, dst)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func trySecureRead(f *os.File) (string, error) {
	var val string
	fd := int(f.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(int(f.Fd()))
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		val = string(b)
	}
	return val, nil
}
