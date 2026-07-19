package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

type PolicyHandler struct {
	gatewayURL       string
	policyReadSecret string
	client           *http.Client

	mu          sync.RWMutex
	statusCache *cachedResponse
	sugCache    *cachedResponse
}

type cachedResponse struct {
	data      json.RawMessage
	fetchedAt time.Time
}

const cacheTTL = 30 * time.Second

func NewPolicyHandler(gatewayURL, policyReadSecret string) *PolicyHandler {
	return &PolicyHandler{
		gatewayURL:       gatewayURL,
		policyReadSecret: policyReadSecret,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (h *PolicyHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	data, err := h.cachedFetch(&h.statusCache, "GET", "/api/self-healing/status")
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *PolicyHandler) GetSuggestions(w http.ResponseWriter, r *http.Request) {
	data, err := h.cachedFetch(&h.sugCache, "POST", "/api/self-healing/suggestions")
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *PolicyHandler) cachedFetch(slot **cachedResponse, method, path string) (json.RawMessage, error) {
	h.mu.RLock()
	cached := *slot
	h.mu.RUnlock()

	if cached != nil && time.Since(cached.fetchedAt) < cacheTTL {
		return cached.data, nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Double-check after acquiring write lock
	cached = *slot
	if cached != nil && time.Since(cached.fetchedAt) < cacheTTL {
		return cached.data, nil
	}

	req, err := http.NewRequest(method, h.gatewayURL+path, nil)
	if err != nil {
		return nil, err
	}
	if h.policyReadSecret != "" {
		req.Header.Set("Authorization", "Bearer "+h.policyReadSecret)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &upstreamError{status: resp.StatusCode, body: string(body)}
	}

	*slot = &cachedResponse{data: body, fetchedAt: time.Now()}
	return body, nil
}

type upstreamError struct {
	status int
	body   string
}

func (e *upstreamError) Error() string {
	return "gateway returned " + http.StatusText(e.status)
}
