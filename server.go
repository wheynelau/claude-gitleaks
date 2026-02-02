package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Proxy handles incoming requests, scans for leaks, and forwards to upstream.
type Proxy struct {
	upstream     *url.URL
	client       *http.Client
	scanner      *Scanner
	rejectOnLeak bool
	tracer       trace.Tracer
}

// NewProxy creates a new proxy with the given configuration.
func NewProxy(upstreamURL string, rejectOnLeak bool, configPath string, logger *slog.Logger) (*Proxy, error) {
	upstream, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream URL: %w", err)
	}

	scanner, err := NewScanner(configPath, logger)
	if err != nil {
		return nil, fmt.Errorf("create scanner: %w", err)
	}

	return &Proxy{
		upstream:     upstream,
		client:       &http.Client{},
		scanner:      scanner,
		rejectOnLeak: rejectOnLeak,
		tracer:       otel.Tracer("gitleaks-proxy"),
	}, nil
}

func (p *Proxy) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	result := p.scanner.Scan(string(body))
	redacted := redactSecrets(string(body), result.Secrets)

	// Generate findings for debug response
	findings := make([]string, len(result.Secrets))
	for i, secret := range result.Secrets {
		findings[i] = fmt.Sprintf("Secret %d: %s", i+1, truncate(secret))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"redacted": redacted,
		"count":    len(result.Secrets),
		"findings": findings,
	})
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// scan is meant for testing, just do a post request
	if r.URL.Path == "/scan" {
		p.handleScan(w, r)
		return
	}

	ctx := r.Context()
	slog.Info("request received", "method", r.Method, "path", r.URL.Path)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// Scan and optionally redact secrets
	if len(body) > 0 {
		// span for tracing
		var span trace.Span
		ctx, span = p.tracer.Start(ctx, "check_leaks",
			trace.WithAttributes(attribute.Int("body.size", len(body))))

		// should we log the secrets in the traces?
		result := p.scanner.ScanRequestBody(body)
		span.SetAttributes(
			attribute.Int("leaks.found", len(result.Secrets)),
			attribute.Bool("leaks.detected", len(result.Secrets) > 0),
		)
		span.End()

		if len(result.Secrets) > 0 {
			slog.Warn("leaks detected in request", "count", len(result.Secrets))
			if p.rejectOnLeak {
				http.Error(w, "Request rejected: API key leak detected", http.StatusBadRequest)
				return
			}
			body = []byte(redactSecrets(string(body), result.Secrets))
			slog.Info("secrets redacted", "count", len(result.Secrets))
		}
	}

	p.forwardRequest(ctx, w, r, body)
}

func (p *Proxy) forwardRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte) {
	target := *p.upstream
	target.Path = r.URL.Path
	target.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}

	copyHeaders(req.Header, r.Header, "host", "content-length")

	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to contact upstream: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// copyHeaders copies headers from src to dst, excluding specified keys.
func copyHeaders(dst, src http.Header, exclude ...string) {
	excludeSet := make(map[string]struct{}, len(exclude))
	for _, k := range exclude {
		excludeSet[strings.ToLower(k)] = struct{}{}
	}
	for key, values := range src {
		if _, skip := excludeSet[strings.ToLower(key)]; skip {
			continue
		}
		for _, v := range values {
			dst.Add(key, v)
		}
	}
}

func redactSecrets(text string, secrets []string) string {
	for _, secret := range secrets {
		text = strings.ReplaceAll(text, secret, "<REDACTED_KEY>")
	}
	return text
}
