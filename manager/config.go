package manager

import (
	"log"

	"github.com/Netflix/go-env"
)

// Config returns the module config
type Config struct {
	JWT   JWT
	Redis Redis
}

// NewConfig returns a loaded module config
func NewConfig() *Config {
	var config Config
	_, err := env.UnmarshalFromEnviron(&config)
	if err != nil {
		log.Fatal(err)
	}

	return &config
}
