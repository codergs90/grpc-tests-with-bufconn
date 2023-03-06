package test

import (
	"context"

	greetv1 "github.com/buffioconnect/gen/go/protos/greet/v1"
)

// greetServiceServer implements the GreetService API.
type greetServiceServer struct {
	greetv1.UnimplementedGreetServiceServer
}

// SayHello replies back with welcome message to the caller.
func (s *greetServiceServer) SayHello(ctx context.Context, req *greetv1.GreetServiceSayHelloRequest) (*greetv1.GreetServiceSayHelloResponse, error) {
	return &greetv1.GreetServiceSayHelloResponse{
		Message: "hello " + req.GetName(),
	}, nil
}
