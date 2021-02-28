package grpc

import (
	"context"
	"fmt"

	"github.com/easeq/go-redis-access-control/manager"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AuthInterceptor is a grpc interceptor for authentication and authorization
type AuthInterceptor struct {
	jwtManager *manager.JWT
}

// NewAuthInterceptor returns a new auth interceptor
func NewAuthInterceptor(jwtManager *manager.JWT) *AuthInterceptor {
	return &AuthInterceptor{jwtManager}
}

// Unary returns a server interceptor function to authenticate and authorize unary RPC
func (interceptor *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		err := interceptor.authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// Stream returns a server interceptor function to authenticate and authorize stream RPC
func (interceptor *AuthInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		err := interceptor.authorize(stream.Context(), info.FullMethod)
		if err != nil {
			return err
		}

		return handler(srv, stream)
	}
}

// matchCsrfToken returns whether the current token is valid
func (interceptor *AuthInterceptor) matchCsrfToken(requestToken string, claimsToken string) bool {
	return requestToken == claimsToken
}

// Authorize access to user
func (interceptor *AuthInterceptor) authorize(ctx context.Context, endpoint string) error {
	if manager.Endpoint(endpoint).CanAccessWithoutAuth() == true {
		return nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "missing required data")
	}

	accessToken, err := MetadataByKey(md, "authorization")
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "access token is required")
	}

	claims, err := interceptor.jwtManager.Verify(accessToken)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "access token is invalid: %v", err)
	}

	if manager.Endpoint(endpoint).CanAccessWithRole(claims.Role) == false {
		return status.Errorf(codes.PermissionDenied, "access denied!")
	}

	csrfToken, _ := MetadataByKey(md, "X-XSRF-TOKEN")
	if interceptor.matchCsrfToken(csrfToken, claims.RandomToken) {
		return status.Error(codes.PermissionDenied, "access denied!")
	}

	return nil
}

// MetadataByKey returns the value of the first metadata with the provided key
func MetadataByKey(md metadata.MD, key string) (string, error) {
	values := md.Get(key)
	if len(values) == 0 {
		return "", fmt.Errorf("Value %s is required", key)
	}

	return values[0], nil
}
