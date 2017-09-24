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
	Store(c *CacheableCredentials) error
	ExpirationTime() time.Time
}

type CacheableCredentials struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      int64
}

type CachedCredentials struct {
	Credentials CacheableCredentials
}

type CredentialsCacherProvider struct {
	CacheFilename string
	credentials.Expiry
	CachedCredentials
}

func (p *CredentialsCacherProvider) Store(c *CacheableCredentials) error {
	data, err := json.Marshal(CachedCredentials{Credentials: *c})
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

func (p *CredentialsCacherProvider) ExpirationTime() time.Time {
	return time.Unix(p.Credentials.Expiration, 0)
}

func (p *CredentialsCacherProvider) Retrieve() (credentials.Value, error) {
	val := credentials.Value{ProviderName: "CredentialsCacherProvider"}

	data, err := ioutil.ReadFile(p.CacheFilename)
	if err != nil {
		return val, err
	}

	err = json.Unmarshal(data, &p.CachedCredentials)
	if err != nil {
		return val, err
	}

	val.AccessKeyID = p.Credentials.AccessKeyId
	val.SecretAccessKey = p.Credentials.SecretAccessKey
	val.SessionToken = p.Credentials.SessionToken
	exp_t := p.ExpirationTime()

	// Flag credentials to refresh after ~90% of the actual expiration time (6 minutes for default/max
	// credential lifetime of 1h, 90 seconds for minimum credential lifetime of 15m), using the ModTime()
	// of the credential cache file as the anchor for the calculation
	cache_s, err := os.Stat(p.CacheFilename)
	if err == nil {
		window := exp_t.Sub(cache_s.ModTime()) / 10
		p.Expiry.SetExpiration(exp_t, window)
	}

	return val, nil
}

func (p *CredentialsCacherProvider) IsExpired() bool {
	return p.Expiry.IsExpired()
}
