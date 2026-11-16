package config

import "os"

type Config struct {
	Port        string
	Storage     string
	DatabaseURL string
}

func Load() *Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	storage := os.Getenv("STORAGE")
	if storage == "" {
		storage = "memory"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://threat_user:threat_password@localhost:5432/threat_db?sslmode=disable"
	}

	return &Config{
		Port:        port,
		Storage:     storage,
		DatabaseURL: dbURL,
	}
}
