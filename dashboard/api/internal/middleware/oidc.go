package middleware

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

type contextKey string

const UserClaimsKey contextKey = "user_claims"

type UserClaims struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
}

// OIDCAuth validates JWT bearer tokens from dashboard operators.
// If issuer or clientID are empty, OIDC is disabled (dev mode only).
func OIDCAuth(issuer, clientID string) func(http.Handler) http.Handler {
	if issuer == "" || clientID == "" {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		panic("failed to initialize OIDC provider: " + err.Error())
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(auth, "Bearer ")

			idToken, err := verifier.Verify(r.Context(), token)
			if err != nil {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}

			var claims UserClaims
			if err := idToken.Claims(&claims); err != nil {
				http.Error(w, `{"error":"failed to parse claims"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserClaimsKey, &claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GatewayAuth validates the shared HMAC secret the gateway uses for
// ingest endpoints. Dashboard operators never use this path.
func GatewayAuth(secret string) func(http.Handler) http.Handler {
	if secret == "" {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, `{"error":"missing gateway token"}`, http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(auth, "Bearer ")

			if subtle.ConstantTimeCompare([]byte(token), []byte(secret)) != 1 {
				http.Error(w, `{"error":"invalid gateway token"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
