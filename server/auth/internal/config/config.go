package config

import (
	"flag"
	"os"
)

type Config struct {
	GRPCPort    string
	PostgresDSN string
	Secret      string
}

func ReadConfig() Config {
	grpcPort := flag.String("g", ":3200", "gRPC server port")
	postgresDSN := flag.String("d", "", "Postgres DSN")

	flag.Parse()

	secret := os.Getenv("SECRET")

	cfg := Config{
		GRPCPort:    *grpcPort,
		PostgresDSN: *postgresDSN,
		Secret:      secret,
	}

	return cfg
}
