package grpcclient

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/trunov/goph-keeper/server/http/pb"
)

func NewAuthClient(grpcServerAddress string) (pb.AuthClient, error) {
	conn, err := grpc.Dial(grpcServerAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return pb.NewAuthClient(conn), nil
}
