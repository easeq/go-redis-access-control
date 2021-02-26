package manager

import (
	"context"

	"github.com/go-redis/redis/v8"
	"github.com/rbcervilla/redisstore/v8"
)

// Redis config
type Redis struct {
	Address          string `env:"GRAL_REDIS_ADDRESS"`
	DefaultSessionID string `env:"GRAL_DEFAULT_SESSION_ID"`
	SessionTimeout   int    `env:"GRAL_SESSION_TIMEOUT"`
	CSRFTokenLength  int    `env:"GRAL_CSRF_TOKEN_LENGTH"`
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
