package config

import "flag"

type Config struct {
	PostgresDSN string
}

func ReadConfig() Config {
	postgresDSN := flag.String("d", "", "Postgres DSN")

	flag.Parse()

	cfg := Config{
		PostgresDSN: *postgresDSN,
	}

	return cfg
}
