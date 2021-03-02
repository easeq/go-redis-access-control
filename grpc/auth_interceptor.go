package grpc

import (
	"context"
	"fmt"
	"log"

	"github.com/easeq/go-redis-access-control/gateway"
	"github.com/easeq/go-redis-access-control/manager"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	// ErrMissingReqData returns when the certain required data is missing
	ErrMissingReqData = status.Errorf(codes.Unauthenticated, "Missing required data")
	// ErrMissingAccessToken returns when access token is missing from the request data
	ErrMissingAccessToken = status.Errorf(codes.Unauthenticated, "Access token is required")
	// ErrInvalidAccessToken returns when the access token provided is invalid
	ErrInvalidAccessToken = status.Errorf(codes.Unauthenticated, "Access token is invalid")
	// ErrAccessDenied returns when the data provided is not sufficient to provide access to the requested method
	ErrAccessDenied = status.Errorf(codes.PermissionDenied, "Access denied")
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

// Authorize access to user
func (interceptor *AuthInterceptor) authorize(ctx context.Context, endpoint string) error {
	if manager.Endpoint(endpoint).CanAccessWithoutAuth() == true {
		return nil
	}

	md, ok := getMetaDataFromContext(ctx)
	if !ok {
		return ErrMissingReqData
	}

	accessToken, err := MetadataByKey(md, gateway.KeyAuthorization)
	if err != nil {
		return ErrMissingAccessToken
	}

	claims, err := interceptor.jwtManager.Verify(accessToken)
	if err != nil {
		return ErrInvalidAccessToken
	}

	if manager.Endpoint(endpoint).CanAccessWithRole(claims.Role) == false {
		return ErrAccessDenied
	}

	csrfToken, _ := MetadataByKey(md, gateway.KeyUserCSRFToken)
	if !claims.RandomToken.Compare(csrfToken) {
		return ErrAccessDenied
	}

	return nil
}

// SetSessionData sets the data to be stored in the session store.
// The values are passed as a map of (string) key => (string) value
func SetSessionData(ctx context.Context, kv ...string) {
	header := metadata.Pairs(kv...)
	grpc.SendHeader(ctx, header)
}

// MetadataByKey returns the value of the first metadata with the provided key
func MetadataByKey(md metadata.MD, key string) (string, error) {
	values := md.Get(key)
	if len(values) == 0 {
		return "", fmt.Errorf("Value %s is required", key)
	}

	return values[0], nil
}

func getMetaDataFromContext(ctx context.Context) (metadata.MD, bool) {
	return metadata.FromIncomingContext(ctx)
}

// GetCurrentUserID returns the current user's ID
func GetCurrentUserID(ctx context.Context) (string, error) {
	md, _ := getMetaDataFromContext(ctx)
	log.Print(md)
	return MetadataByKey(md, gateway.KeyUserID)
}

// GetCurrentUserRole returns the current user's role
func GetCurrentUserRole(ctx context.Context) (string, error) {
	md, _ := getMetaDataFromContext(ctx)
	return MetadataByKey(md, gateway.KeyUserRole)
}
