package config

import (
	"github.com/mbndr/logo"
)

// ChainConfigHandler is a handler which will delegate the configuration lookup to a list of
// ConfigHandlers.  Unlike the SDK ChainCredentials provider, which stops at the first
// credentials, this handler gathers configuration from all handlers.
type ChainConfigHandler struct {
	handlers []ConfigHandler
	log      *logo.Logger
}

// NewChainConfigHandler returns a new chained ConfigHandler configured with the given
// ConfigHandlerOpts and ConfigHandler list
func NewChainConfigHandler(opts *ConfigHandlerOpts, h ...ConfigHandler) ConfigHandler {
	ch := &ChainConfigHandler{handlers: h}
	if opts != nil {
		ch.log = NewLogger("ChainConfigHandler", opts.LogLevel)
	}
	return ch
}

// Add appends the provided ConfigHandler to the chain of handlers.  Returns the updated
// handler object so this call can be chained as well.
func (h *ChainConfigHandler) Add(ch ConfigHandler) ConfigHandler {
	h.handlers = append(h.handlers, ch)
	return h
}

// Config calls the Config() function on each of the configured handlers using the provided
// AwsConfig object.  All providers in the chain must succeed. The first call to the
// underlying Config() which fails will be reported back
func (h *ChainConfigHandler) Config(c *AwsConfig) error {
	if c == nil {
		return nil
	}

	for _, i := range h.handlers {
		if err := i.Config(c); err != nil {
			if h.log != nil {
				h.log.Debugf("Error loading config from %T: %v", i, err)
			}
			return err
		}
	}

	return nil
}
