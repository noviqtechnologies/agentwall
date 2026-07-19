package handler

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/model"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/sse"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/store"
)

type IngestHandler struct {
	store  *store.Store
	broker *sse.Broker
}

func NewIngestHandler(s *store.Store, b *sse.Broker) *IngestHandler {
	return &IngestHandler{store: s, broker: b}
}

// PostEvent handles POST /api/v1/ingest/events from the gateway.
// Accepts only the RedactedEvent JSON shape — any unknown fields are rejected.
func (h *IngestHandler) PostEvent(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var event model.RedactedEvent
	if err := dec.Decode(&event); err != nil {
		http.Error(w, `{"error":"invalid event payload"}`, http.StatusBadRequest)
		return
	}
	if !event.Valid() {
		http.Error(w, `{"error":"event failed validation"}`, http.StatusUnprocessableEntity)
		return
	}

	ctx := r.Context()
	if err := h.store.UpsertAgent(ctx, event.AgentID); err != nil {
		log.Printf("upsert agent: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if err := h.store.InsertEvent(ctx, &event); err != nil {
		log.Printf("insert event: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// PostAlert handles POST /api/v1/ingest/alerts from the gateway.
// Persists the alert and fans out to SSE subscribers (AC-23.2).
func (h *IngestHandler) PostAlert(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var alert model.RedactedAlert
	if err := dec.Decode(&alert); err != nil {
		http.Error(w, `{"error":"invalid alert payload"}`, http.StatusBadRequest)
		return
	}
	if !alert.Valid() {
		http.Error(w, `{"error":"alert failed validation"}`, http.StatusUnprocessableEntity)
		return
	}

	ctx := r.Context()

	if err := h.store.UpsertAgent(ctx, alert.Event.AgentID); err != nil {
		log.Printf("upsert agent: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if err := h.store.InsertEvent(ctx, &alert.Event); err != nil {
		log.Printf("insert event for alert: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if err := h.store.InsertAlert(ctx, &alert); err != nil {
		log.Printf("insert alert: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Fan out to SSE — non-blocking, never fails the ingest.
	h.broker.Publish(alert)

	w.WriteHeader(http.StatusCreated)
}

// PostCredential handles POST /api/v1/ingest/credentials from the gateway.
func (h *IngestHandler) PostCredential(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var cred model.SanitizedCredentialMeta
	if err := dec.Decode(&cred); err != nil {
		http.Error(w, `{"error":"invalid credential payload"}`, http.StatusBadRequest)
		return
	}
	if cred.CredentialID == "" || cred.AgentID == "" {
		http.Error(w, `{"error":"credential failed validation"}`, http.StatusUnprocessableEntity)
		return
	}

	ctx := r.Context()
	if err := h.store.UpsertAgent(ctx, cred.AgentID); err != nil {
		log.Printf("upsert agent: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if err := h.store.UpsertCredential(ctx, &cred); err != nil {
		log.Printf("upsert credential: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
