package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/evergreenos/selfhost-backend/internal/config"
	"github.com/evergreenos/selfhost-backend/internal/server"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config/config.yaml", "Path to configuration file")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	app, err := server.NewApp(cfg)
	if err != nil {
		log.Fatalf("init app: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Start(ctx); err != nil {
		log.Fatalf("start app: %v", err)
	}

	slog.Info("EvergreenOS Selfhost Backend started",
		slog.String("grpc_addr", app.GRPCAddr()),
		slog.String("rest_addr", app.RESTAddr()),
		slog.String("metrics_addr", app.MetricsAddr()),
	)

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := app.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("shutdown app: %v", err)
	}
}
