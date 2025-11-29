package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/example/auth-service/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	application, err := app.New(ctx)
	if err != nil {
		log.Fatalf("failed to init app: %v", err)
	}
	defer application.Close()

	if err := application.Run(ctx); err != nil {
		log.Printf("app stopped: %v", err)
	}
}
