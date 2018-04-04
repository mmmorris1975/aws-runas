package lib

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/mbndr/logo"
	"io/ioutil"
	"os"
	"path/filepath"
)

// A credentials.Value compatible set of credentials with the
// addition of expiration information, able to be serialized to a file
type CachableCredentials struct {
	credentials.Value
	credentials.Expiry `json:"-"` // do not marshal
	Expiration         int64
}

type CredentialsCacher interface {
	Fetch() (*CachableCredentials, error)
	Store(c *CachableCredentials) error
	CacheFile() string
}

type CredentialsCacherOptions struct {
	LogLevel logo.Level
}

type credentialsCacher struct {
	file string
	log  *logo.Logger
}

func NewCredentialsCacher(file string, opts *CredentialsCacherOptions) CredentialsCacher {
	if len(file) < 1 {
		panic("invalid file argument to NewCredentialsCacher")
	}

	if opts == nil {
		opts = new(CredentialsCacherOptions)
	}

	c := new(credentialsCacher)
	c.file = file
	c.log = logo.NewSimpleLogger(os.Stderr, opts.LogLevel, "aws-runas.CredentialsCacher", true)
	return c
}

func (c *credentialsCacher) CacheFile() string {
	return c.file
}

func (c *credentialsCacher) Fetch() (*CachableCredentials, error) {
	creds := new(CachableCredentials)

	data, err := ioutil.ReadFile(c.file)
	if err != nil {
		return nil, err
	}
	c.log.Debugf("Read data from %s", c.file)

	if err := json.Unmarshal(data, creds); err != nil {
		return nil, err
	}
	c.log.Debugf("Unmarshaled credentials:\n%s", data)

	return creds, nil
}

func (c *credentialsCacher) Store(creds *CachableCredentials) error {
	if creds == nil {
		return fmt.Errorf("nil credentials detected")
	}

	if err := os.MkdirAll(filepath.Dir(c.file), 0755); err != nil {
		return err
	}

	data, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	c.log.Debugf("Marshaled credentials:\n%+s", data)

	if err := ioutil.WriteFile(c.file, data, 0600); err != nil {
		return err
	}
	c.log.Debugf("Wrote credentials to: %s", c.file)

	return nil
}
