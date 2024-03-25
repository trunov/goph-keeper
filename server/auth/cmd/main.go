package main

import (
	"context"
	"log"
	"net"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/trunov/goph-keeper/server/auth/internal/config"
	"github.com/trunov/goph-keeper/server/auth/internal/lib/jwt"
	"github.com/trunov/goph-keeper/server/auth/internal/storage/postgres"
	pb "github.com/trunov/goph-keeper/server/auth/proto"
	"google.golang.org/grpc"
)

func main() {
	cfg := config.ReadConfig()

	if cfg.Secret == "" || cfg.PostgresDSN == "" {
		log.Fatal("Secret or PostgresDSN should be provided")
	}

	ctx := context.Background()

	listen, err := net.Listen("tcp", cfg.GRPCPort)
	if err != nil {
		log.Fatal(err)
	}

	grpcServer := grpc.NewServer()

	dbpool, err := pgxpool.Connect(ctx, cfg.PostgresDSN)
	if err != nil {
		log.Fatal(err)
	}

	storage := postgres.NewDBStorage(dbpool)
	jwtService := jwt.NewJWTService(cfg.Secret)

	authServer := NewAuthServer(storage, jwtService)

	pb.RegisterAuthServer(grpcServer, authServer)

	log.Printf("Running GRPC on port %s", cfg.GRPCPort)
	if err := grpcServer.Serve(listen); err != nil {
		log.Fatal(err)
	}
}
