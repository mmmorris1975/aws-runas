package main

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

type CredentialsCacher interface {
	Store(c *AssumeRoleCredentials) error
}

// This should be compatible with the Credentials portion
// of the awscli credential cache json file.
type AssumeRoleCredentials struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

type CredentialsCacherProvider struct {
	credentials.Expiry
	CacheFilename string
	Credentials   AssumeRoleCredentials
}

func (p *CredentialsCacherProvider) Store(c *AssumeRoleCredentials) error {
	data, err := json.Marshal(*c)
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Dir(p.CacheFilename), 0750)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(p.CacheFilename, data, 0600)
	if err != nil {
		return err
	}

	return nil
}

func (p *CredentialsCacherProvider) Retrieve() (credentials.Value, error) {
	val := credentials.Value{ProviderName: "CredentialsCacherProvider"}

	data, err := ioutil.ReadFile(p.CacheFilename)
	if err != nil {
		return val, err
	}

	err = json.Unmarshal(data, &p.Credentials)
	if err != nil {
		return val, err
	}

	val.AccessKeyID = p.Credentials.AccessKeyId
	val.SecretAccessKey = p.Credentials.SecretAccessKey
	val.SessionToken = p.Credentials.SessionToken
	p.Expiry.SetExpiration(p.Credentials.Expiration, time.Duration(60)*time.Second)

	return val, nil
}

func (p *CredentialsCacherProvider) IsExpired() bool {
	return p.Expiry.IsExpired()
}
