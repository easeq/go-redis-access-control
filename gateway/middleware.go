package gateway

import (
	"context"
	"net/http"
)

// Custom type for contextKey
type contextKey int

const (
	// Unique key used to store the http request in the context
	requestContextKey contextKey = 0
)

// Middleware adds request to context
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		ctx = context.WithValue(ctx, requestContextKey, r)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
