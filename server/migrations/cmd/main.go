package main

import (
	"log"

	"github.com/trunov/goph-keeper/server/migrations/internal/config"
	"github.com/trunov/goph-keeper/server/migrations/internal/migrate"
)

func main() {
	cfg := config.ReadConfig()

	if cfg.PostgresDSN == "" {
		log.Fatal("postgresDSN is missing")
	}

	err := migrate.Migrate(cfg.PostgresDSN, migrate.Migrations)

	if err != nil {
		log.Fatal(err)
	}
}
