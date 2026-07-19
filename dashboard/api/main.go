package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/config"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/handler"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/middleware"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/sse"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if cfg.DevMode {
		log.Println("WARNING: running in DEV_MODE — all auth is disabled. DO NOT deploy to production.")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	db, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()

	broker := sse.NewBroker()

	ingestH := handler.NewIngestHandler(db, broker)
	fleetH := handler.NewFleetHandler(db)
	identityH := handler.NewIdentityHandler(db)
	alertH := handler.NewAlertHandler(db, broker)
	policyH := handler.NewPolicyHandler(cfg.GatewayURL, cfg.PolicyReadSecret)

	r := chi.NewRouter()
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))

	// Health check — no auth.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Ingest endpoints — gateway auth (shared secret), NOT OIDC.
	r.Route("/api/v1/ingest", func(r chi.Router) {
		r.Use(middleware.GatewayAuth(cfg.GatewaySecret))
		r.Post("/events", ingestH.PostEvent)
		r.Post("/alerts", ingestH.PostAlert)
		r.Post("/credentials", ingestH.PostCredential)
	})

	// Dashboard API — OIDC auth for human operators.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(middleware.OIDCAuth(cfg.OIDCIssuer, cfg.OIDCClientID))

		r.Get("/fleet/overview", fleetH.GetOverview)
		r.Get("/fleet/agents", fleetH.ListAgents)
		r.Get("/fleet/heatmap", fleetH.GetHeatmap)
		r.Get("/fleet/events", fleetH.ListEvents)
		r.Get("/fleet/agents/{agentID}/events", fleetH.ListEvents)

		r.Get("/identity/credentials", identityH.ListCredentials)

		r.Get("/alerts/recent", alertH.ListRecent)
		r.Get("/alerts/stream", alertH.Stream)

		r.Get("/policy/status", policyH.GetStatus)
		r.Post("/policy/suggestions", policyH.GetSuggestions)
	})

	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // SSE streams need unbounded writes
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("dashboard-api listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)
}
