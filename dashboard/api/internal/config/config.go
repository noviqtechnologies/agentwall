package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Port        int
	DatabaseURL string

	OIDCIssuer   string
	OIDCClientID string

	// GatewaySecret is a shared HMAC key the gateway includes in the
	// Authorization header when POSTing to the ingest endpoints.
	// Dashboard operators do NOT use this — they use OIDC.
	GatewaySecret string

	// PolicyReadSecret authenticates dashboard-api → gateway requests for
	// self-healing/policy-read endpoints. Separate trust boundary from
	// GatewaySecret (which is gateway → dashboard-api for ingest).
	PolicyReadSecret string

	// GatewayURL is the internal URL of the AgentWall gateway (e.g.
	// http://agentwall-gateway:8080). Used to proxy policy-read requests.
	GatewayURL string

	// DevMode disables auth requirements. Requires BOTH DEV_MODE=true AND
	// ALLOW_DEV_MODE=true to activate — prevents accidental copy-paste of
	// dev config into production Helm values.
	DevMode bool
}

func Load() (*Config, error) {
	port := 8400
	if v := os.Getenv("DASHBOARD_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid DASHBOARD_PORT: %w", err)
		}
		port = p
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	devMode := os.Getenv("DEV_MODE") == "true" && os.Getenv("ALLOW_DEV_MODE") == "true"

	gatewaySecret := os.Getenv("GATEWAY_SECRET")
	policyReadSecret := os.Getenv("POLICY_READ_SECRET")
	gatewayURL := os.Getenv("GATEWAY_URL")
	oidcIssuer := os.Getenv("OIDC_ISSUER")
	oidcClientID := os.Getenv("OIDC_CLIENT_ID")

	if !devMode {
		if gatewaySecret == "" {
			return nil, fmt.Errorf("GATEWAY_SECRET is required (set DEV_MODE=true and ALLOW_DEV_MODE=true to disable auth for local development)")
		}
		if oidcIssuer == "" || oidcClientID == "" {
			return nil, fmt.Errorf("OIDC_ISSUER and OIDC_CLIENT_ID are required (set DEV_MODE=true and ALLOW_DEV_MODE=true to disable auth for local development)")
		}
	}

	return &Config{
		Port:             port,
		DatabaseURL:      dbURL,
		OIDCIssuer:       oidcIssuer,
		OIDCClientID:     oidcClientID,
		GatewaySecret:    gatewaySecret,
		PolicyReadSecret: policyReadSecret,
		GatewayURL:       gatewayURL,
		DevMode:          devMode,
	}, nil
}
