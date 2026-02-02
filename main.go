package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

func main() {
	if err := run(); err != nil {
		slog.Error("application error", "error", err)
		os.Exit(1)
	}
}

func run() (err error) {
	// Parse command line flags
	rejectOnLeak := flag.Bool("reject", false, "reject requests with detected API key leaks instead of redacting")
	configPath := flag.String("config", "", "path to gitleaks config file (uses default config if not specified)")
	port := flag.Int("port", 8000, "port to run the proxy on")
	host := flag.String("host", "", "host to bind to (empty = all interfaces)")
	debug := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()

	// Setup structured logging with JSON output to stdout
	logLevel := slog.LevelInfo
	if *debug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Handle SIGINT (CTRL+C) gracefully
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Set up OpenTelemetry
	otelShutdown, err := setupOTelSDK(ctx)
	if err != nil {
		return err
	}
	// Handle shutdown properly so nothing leaks
	defer func() {
		err = errors.Join(err, otelShutdown(context.Background()))
	}()

	// Get upstream URL from environment or use default
	upstreamURL := os.Getenv("ANTHROPIC_BASE_URL")
	if upstreamURL == "" {
		upstreamURL = "https://api.anthropic.com"
	}

	proxy, err := NewProxy(upstreamURL, *rejectOnLeak, *configPath, logger)
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}

	// Wrap proxy with OTEL HTTP instrumentation
	handler := otelhttp.NewHandler(proxy, "claude-gitleaks")

	proxyAddr := fmt.Sprintf("%s:%d", *host, *port)

	srv := &http.Server{
		Addr:         proxyAddr,
		BaseContext:  func(net.Listener) context.Context { return ctx },
		ReadTimeout:  time.Second * 30,
		WriteTimeout: time.Second * 90,
		Handler:      handler,
	}

	slog.Info("proxy server starting", "addr", proxyAddr, "upstream", upstreamURL)

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- srv.ListenAndServe()
	}()

	// Wait for interruption
	select {
	case err = <-srvErr:
		// Error when starting HTTP server
		return err
	case <-ctx.Done():
		// Wait for first CTRL+C
		// Stop receiving signal notifications as soon as possible
		stop()
	}

	// When Shutdown is called, ListenAndServe immediately returns ErrServerClosed
	slog.Info("shutting down server gracefully")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = srv.Shutdown(shutdownCtx)
	return err
}
