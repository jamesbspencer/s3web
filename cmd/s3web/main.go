package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"s3web/internal/config"
	"s3web/internal/server"
	"s3web/internal/storage"
	"s3web/internal/store"
)

func main() {
	cfg := config.Load()

	log.Printf("[s3web] starting (mode=%s, bucket=%s, listen=%s)", cfg.BackendMode, cfg.S3Bucket, cfg.ListenAddr)

	metaStore, err := store.NewLocalStore(cfg.LocalDataDir)
	if err != nil {
		log.Fatalf("[s3web] failed to initialize metadata store: %v", err)
	}

	objStorage, err := storage.NewLocalFSStorage(cfg.LocalDataDir)
	if err != nil {
		log.Fatalf("[s3web] failed to initialize object storage: %v", err)
	}

	srv, err := server.New(cfg, metaStore, objStorage)
	if err != nil {
		log.Fatalf("[s3web] failed to initialize HTTP server: %v", err)
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 30 * time.Second,
		// Extended idle/write timeouts for multi-GB ISO transfers over private VPN & Internal ALB
		IdleTimeout:  3600 * time.Second,
		ReadTimeout:  3600 * time.Second,
		WriteTimeout: 3600 * time.Second,
	}

	go func() {
		log.Printf("[s3web] listening on %s (Web UI: %s | HTML Raw Access: %s/raw/)", cfg.ListenAddr, cfg.BaseURL, cfg.BaseURL)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[s3web] HTTP server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Printf("[s3web] shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}

