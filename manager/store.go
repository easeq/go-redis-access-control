package manager

import (
	"context"

	"github.com/go-redis/redis/v8"
	"github.com/rbcervilla/redisstore/v8"
)

// Redis config
type Redis struct {
	Address          string `env:"GRAC_REDIS_ADDRESS,default=localhost:6379"`
	DefaultSessionID string `env:"GRAC_DEFAULT_SESSION_ID,default=__sess-id"`
	SessionDomain    string `env:"GRAC_SESSION_DOMAIN"`
	SessionTimeout   int    `env:"GRAC_SESSION_TIMEOUT,default=3600"`
	SecureCookie     bool   `env:"GRAC_SECURE_COOKIE,default=true"`
	SameSite         int    `env:"GRAC_COOKIE_SAMESITE,default=3"`
	CSRFTokenLength  int    `env:"GRAC_CSRF_TOKEN_LENGTH,default=128"`
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
