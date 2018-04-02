package config

import (
	"github.com/mbndr/logo"
	"os"
	"time"
)

// The options available for configuration by this handler.
type CmdlineOptions struct {
	Profile       string
	RoleArn       string
	MfaSerial     string
	TokenDuration string
	CredDuration  string
}

// A ConfigHandler to set various configuration options via command line
// parameters.  This may be of limited utility outside of the aws-runas cli
type CmdlineConfigHandler struct {
	opts *CmdlineOptions
	log  *logo.Logger
}

// Create a new ConfigHandler with the provided handler options
// and CmdlineOptions.
func NewCmdlineConfigHandler(handlerOpts *ConfigHandlerOpts, cmdlineOpts *CmdlineOptions) ConfigHandler {
	h := &CmdlineConfigHandler{opts: cmdlineOpts}
	if handlerOpts != nil {
		h.log = logo.NewSimpleLogger(os.Stderr, handlerOpts.LogLevel, "CmdlineConfigHandler", true)
	}
	return h
}

// Set the provided command line options in the Config struct
func (h *CmdlineConfigHandler) Config(c *AwsConfig) error {
	if c == nil {
		return nil
	}

	opts := h.opts

	if len(opts.Profile) > 0 {
		c.Name = opts.Profile
	}

	if len(opts.RoleArn) > 0 {
		c.RoleArn = opts.RoleArn
	}

	if len(opts.MfaSerial) > 0 {
		c.MfaSerial = opts.MfaSerial
	}

	if len(opts.CredDuration) > 0 {
		d, err := time.ParseDuration(opts.CredDuration)
		if err != nil {
			return err
		}
		c.CredDuration = d
	}

	if len(opts.TokenDuration) > 0 {
		d, err := time.ParseDuration(opts.TokenDuration)
		if err != nil {
			return err
		}
		c.SessionDuration = d
	}

	return nil
}
