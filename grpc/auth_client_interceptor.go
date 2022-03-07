package grpc

import (
	"context"
	"fmt"

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
		md, err := GetAuthMD(uid, role, sessionKey)
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
		md, err := GetAuthMD(uid, role, sessionKey)
		if err != nil {
			return nil, fmt.Errorf("Stream client auth error: %v", err)
		}

		newCtx := metadata.NewOutgoingContext(ctx, md)
		return streamer(newCtx, desc, cc, method, opts...)
	}
}
