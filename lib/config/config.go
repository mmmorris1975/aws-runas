package config

import (
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/mmmorris1975/aws-config/config"
	"net/url"
	"strings"
	"time"
)

// AwsConfig extends aws-config/config.AwsConfig and adds attributes "non-standard" config items
type AwsConfig struct {
	*config.AwsConfig
	CredentialsDuration  time.Duration
	SessionTokenDuration time.Duration
	JumpRoleArn          arn.ARN
	SamlAuthUrl          *url.URL
	SamlUsername         string
	SamlProvider         string
}

// Wrap converts an aws-config/config.AwsConfig type to our local AwsConfig type
func Wrap(c *config.AwsConfig) (*AwsConfig, error) {
	t := AwsConfig{
		AwsConfig:    c,
		SamlUsername: c.Get("saml_username"),
		SamlProvider: strings.ToLower(c.Get("saml_provider")),
	}

	if c.DurationSeconds < 1 {
		cd, err := time.ParseDuration(c.Get("credentials_duration"))
		if err != nil {
			cd = 0
		}
		t.CredentialsDuration = cd
		t.DurationSeconds = int(cd.Seconds())
	}

	sd, err := time.ParseDuration(c.Get("session_token_duration"))
	if err != nil {
		sd = 0
	}
	t.SessionTokenDuration = sd

	jr := c.Get("jump_role_arn")
	if len(jr) > 0 {
		a, err := arn.Parse(c.Get("jump_role_arn"))
		if err != nil {
			return nil, err
		}
		t.JumpRoleArn = a
	}

	sm := c.Get("saml_auth_url")
	if len(sm) > 0 {
		u, err := url.Parse(c.Get("saml_auth_url"))
		if err != nil {
			return nil, err
		}
		t.SamlAuthUrl = u
	}

	return &t, nil
}
