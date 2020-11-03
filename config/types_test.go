package config

import (
	"errors"
	"time"
)

type badLoader bool

func (l *badLoader) Config(string, ...interface{}) (*AwsConfig, error) {
	return nil, errors.New("bad config")
}

func (l *badLoader) Credentials(string, ...interface{}) (*AwsCredentials, error) {
	return nil, errors.New("bad credentials")
}

type simpleLoader bool

func (l *simpleLoader) Config(string, ...interface{}) (*AwsConfig, error) {
	c := &AwsConfig{
		Region: "mockRegion",
	}
	return c, nil
}

func (l *simpleLoader) Credentials(string, ...interface{}) (*AwsCredentials, error) {
	return new(AwsCredentials), nil
}

type samlLoader bool

func (l *samlLoader) Config(string, ...interface{}) (*AwsConfig, error) {
	c := &AwsConfig{
		CredentialsDuration: 1 * time.Hour,
		RoleArn:             "mockRole",
		SamlUrl:             "https://saml.local/saml",
		SamlUsername:        "mockUser",
	}
	return c, nil
}

func (l *samlLoader) Credentials(string, ...interface{}) (*AwsCredentials, error) {
	return &AwsCredentials{SamlPassword: "mockPassword"}, nil
}

type sourceProfileLoader bool

func (l *sourceProfileLoader) Config(string, ...interface{}) (*AwsConfig, error) {
	src := &AwsConfig{
		CredentialsDuration: 4 * time.Hour,
		MfaSerial:           "mockMfa",
		Region:              "mockRegion",
	}
	c := &AwsConfig{
		ExternalId:    "mockExtId",
		RoleArn:       "mockRole",
		SrcProfile:    "mock",
		sourceProfile: src,
	}
	return c, nil
}

func (l *sourceProfileLoader) Credentials(string, ...interface{}) (*AwsCredentials, error) {
	return new(AwsCredentials), nil
}
