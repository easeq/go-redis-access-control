package manager

import (
	"fmt"

	"github.com/Netflix/go-env"
)

// Config returns the module config
type Config struct {
	JWT   JWT
	Redis Redis
}

// NewConfig returns a loaded module config
func NewConfig() (*Config, error) {
	var config Config
	_, err := env.UnmarshalFromEnviron(&config)
	if err != nil {
		return nil, fmt.Errorf("GRAC config load error: %v", err)
	}

	return &config, nil
}
