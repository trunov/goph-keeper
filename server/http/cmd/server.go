package main

import (
	"context"
	"net/http"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/trunov/goph-keeper/server/http/internal/grpcclient"
	"github.com/trunov/goph-keeper/server/http/internal/handler"
	"github.com/trunov/goph-keeper/server/http/internal/storage/postgres"
	"golang.org/x/crypto/acme/autocert"

	log "github.com/sirupsen/logrus"
)

var (
	Version string
)

const (
	serverAddress     = "localhost:3000"
	grpcServerAddress = "localhost:3200"
	postgresDSN       = "postgres://trunov:9851556332@localhost:5432/gophkeeper?sslmode=disable"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})

	log.SetOutput(os.Stdout)

	log.SetLevel(log.InfoLevel)
}

func StartServer() error {
	ctx := context.Background()

	authClient, err := grpcclient.NewAuthClient(grpcServerAddress)
	if err != nil {
		log.Fatal(err)
	}

	dbpool, err := pgxpool.Connect(ctx, postgresDSN)
	if err != nil {
		log.Fatal(err)
	}

	storage := postgres.NewDBStorage(dbpool)

	var server *http.Server

	h := handler.NewHandler(authClient, storage, Version)
	r := handler.NewRouter(h)

	manager := &autocert.Manager{
		Cache:      autocert.DirCache("cache-dir"),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("gophkeeper.com", "www.gophkeeper.com"),
	}

	server = &http.Server{
		Addr:      serverAddress,
		Handler:   r,
		TLSConfig: manager.TLSConfig(),
	}

	log.Info("server has been started on: ", serverAddress)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
		return err
	}

	return nil
}
