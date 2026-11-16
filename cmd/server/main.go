package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"threat-exchange/internal/api"
	"threat-exchange/internal/config"
	"threat-exchange/internal/repository"
	"threat-exchange/internal/service"
	"threat-exchange/internal/validate"
	"time"
)

func main() {
	cfg := config.Load()
	ctx := context.Background()

	var repo repository.ThreatRepository
	var err error

	if cfg.Storage == "postgres" {
		log.Println("Running database migrations...")
		if err := repository.RunMigrations(cfg.DatabaseURL); err != nil {
			log.Fatalf("Migrations failed: %v", err)
		}
		log.Println("Migrations applied successfully")

		log.Println("Connecting to PostgreSQL..")
		repo, err = repository.NewPostgresRepository(ctx, cfg.DatabaseURL)
		if err != nil {
			log.Fatalf("DB connection failed: %v", err)
		}
		log.Println("Connected to PostgreSQL")
	} else {
		log.Println("Storage: memory")
		repo = repository.NewMemoryRepository()
	}

	validator := validate.New()
	svc := service.NewThreatService(repo)
	handler := api.NewThreatHandler(svc, validator)
	router := api.NewRouter(handler)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		log.Printf("Starting server on port %s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited properly")
}
