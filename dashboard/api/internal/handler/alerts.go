package handler

import (
	"net/http"

	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/sse"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/store"
)

type AlertHandler struct {
	store  *store.Store
	broker *sse.Broker
}

func NewAlertHandler(s *store.Store, b *sse.Broker) *AlertHandler {
	return &AlertHandler{store: s, broker: b}
}

// Stream handles GET /api/v1/alerts/stream — SSE endpoint for real-time
// alert delivery (AC-23.2: DLP finding → alert feed within 1 second).
func (h *AlertHandler) Stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error":"streaming unsupported"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, cleanup := h.broker.Subscribe()
	defer cleanup()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			w.Write(msg)
			flusher.Flush()
		}
	}
}

// ListRecent returns the last N alerts from the database (for initial page load,
// before the SSE stream takes over for real-time updates).
func (h *AlertHandler) ListRecent(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)

	alerts, err := h.store.ListRecentAlerts(r.Context(), limit)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, alerts)
}
