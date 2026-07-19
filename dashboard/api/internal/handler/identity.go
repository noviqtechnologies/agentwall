package handler

import (
	"net/http"

	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/store"
)

type IdentityHandler struct {
	store *store.Store
}

func NewIdentityHandler(s *store.Store) *IdentityHandler {
	return &IdentityHandler{store: s}
}

// ListCredentials returns credential metadata for all agents, or filtered
// by agent_id query param. Never returns credential values (AC-23.10).
func (h *IdentityHandler) ListCredentials(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")

	creds, err := h.store.ListCredentials(r.Context(), agentID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, creds)
}
