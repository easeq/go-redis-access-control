package grpc

import (
	"context"
	"fmt"

	"github.com/easeq/go-redis-access-control/gateway"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// UnaryClientInterceptor returns a unary client interceptor with auth headers
// injected ctx
func UnaryClientInterceptor(uid, role, sessionKey string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req interface{},
		reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		md, err := getAppendedMD(ctx, uid, role, sessionKey)
		if err != nil {
			return fmt.Errorf("Unary client auth error: %v", err)
		}

		newCtx := metadata.NewOutgoingContext(ctx, md)
		return invoker(newCtx, method, req, reply, cc, opts...)
	}
}

// StreamClientInterceptor returns a new streaming client interceptor with auth
// headers injected ctx
func StreamClientInterceptor(uid, role, sessionKey string) grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		md, err := getAppendedMD(ctx, uid, role, sessionKey)
		if err != nil {
			return nil, fmt.Errorf("Stream client auth error: %v", err)
		}

		newCtx := metadata.NewOutgoingContext(ctx, md)
		return streamer(newCtx, desc, cc, method, opts...)
	}
}

func getAppendedMD(ctx context.Context, uid, role, sessionKey string) (metadata.MD, error) {
	requestMetadata, _ := metadata.FromIncomingContext(ctx)
	metadataCopy := requestMetadata.Copy()

	// If an authorization key and token are already set in the context, just
	// go ahead
	if len(requestMetadata[gateway.KeyAuthorization]) > 0 &&
		len(requestMetadata[gateway.KeyUserCSRFToken]) > 0 {
		return metadataCopy, nil
	}

	// Create new tokens for internal requests
	authMD, err := GetAuthMD(uid, role, sessionKey)
	if err != nil {
		return nil, err
	}

	return metadata.Join(metadataCopy, authMD), nil
}
