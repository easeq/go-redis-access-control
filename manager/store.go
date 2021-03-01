package manager

import (
	"context"

	"github.com/go-redis/redis/v8"
	"github.com/rbcervilla/redisstore/v8"
)

// Redis config
type Redis struct {
	Address          string `env:"GRAC_REDIS_ADDRESS"`
	DefaultSessionID string `env:"GRAC_DEFAULT_SESSION_ID"`
	SessionDomain    string `env:"GRAC_SESSION_DOMAIN"`
	SessionTimeout   int    `env:"GRAC_SESSION_TIMEOUT"`
	SecureCookie     bool   `env:"GRAC_SECURE_COOKIE"`
	CSRFTokenLength  int    `env:"GRAC_CSRF_TOKEN_LENGTH"`
}

// NewRedisClient creates a new redis client
func NewRedisClient(address string) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr: address,
	})

	return client
}

// NewRedisStore creates new default RedisStore
func NewRedisStore(ctx context.Context, client *redis.Client) (*redisstore.RedisStore, error) {
	return redisstore.NewRedisStore(ctx, client)
}
