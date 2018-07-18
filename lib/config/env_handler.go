package config

import (
	"github.com/mbndr/logo"
	"os"
	"time"
)

// EnvConfigHandler is ConfigHandler which will lookup some configuration items via
// environment variables.  The currently supported list is:
// AWS_REGION
// AWS_PROFILE
// SESSION_TOKEN_DURATION
// CREDENTIALS_DURATION
type EnvConfigHandler struct {
	regionEnvVar      string
	profileEnvVar     string
	sesDurationEnvVar string
	arDurationEnvVar  string
	log               *logo.Logger
}

// NewEnvConfigHandler creates a new ConfigHandler with the provided options.
func NewEnvConfigHandler(opts *ConfigHandlerOpts) ConfigHandler {
	h := &EnvConfigHandler{
		regionEnvVar:      "AWS_REGION",
		profileEnvVar:     "AWS_PROFILE",
		sesDurationEnvVar: "SESSION_TOKEN_DURATION",
		arDurationEnvVar:  "CREDENTIALS_DURATION",
	}

	if opts != nil {
		h.log = NewLogger("EnvConfigHandler", opts.LogLevel)
	}
	return h
}

// Config will look up the values of each environment variable, and if they exist,
// set the appropriate value in the Config object.
func (h *EnvConfigHandler) Config(c *AwsConfig) error {
	if c == nil {
		return nil
	}

	v, ok := os.LookupEnv(h.regionEnvVar)
	if ok {
		c.Region = v
	}

	v, ok = os.LookupEnv(h.profileEnvVar)
	if ok {
		c.Name = v
	}

	v, ok = os.LookupEnv(h.sesDurationEnvVar)
	if ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return err
		}
		c.SessionDuration = d
	}

	v, ok = os.LookupEnv(h.arDurationEnvVar)
	if ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return err
		}
		c.CredDuration = d
	}

	return nil
}
