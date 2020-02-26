package credentials

import (
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"os"
)

// StdinCredProvider prompts for username and password information via prompts printed on os.Stderr
func StdinCredProvider(u, p string) (string, string, error) {
	var err error

	for len(u) < 1 {
		fmt.Fprint(os.Stderr, "Username: ")
		_, err = fmt.Scanln(&u)
		if err != nil && err != io.EOF {
			return "", "", err
		}
	}

	for len(p) < 1 {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil && err != io.EOF {
			return "", "", err
		}
		fmt.Println()
		p = string(b)
	}

	return u, p, nil
}

// StdinMfaTokenProvider prompts for multi-factor tokens via prompts printed on os.Stderr
func StdinMfaTokenProvider() (string, error) {
	var v string

	fmt.Fprint(os.Stderr, "MFA token code: ")
	_, err := fmt.Scanln(&v)
	if err != nil && err != io.EOF {
		return "", err
	}

	return v, nil
}
