package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pksorensen/pks-agent-pulse/internal/auth"
	"github.com/pksorensen/pks-agent-pulse/internal/model"
	"github.com/pksorensen/pks-agent-pulse/internal/probe"
	"github.com/pksorensen/pks-agent-pulse/internal/report"
	"github.com/pksorensen/pks-agent-pulse/internal/store"
)

type Config struct {
	Addr, AdminToken string
	Store            *store.Store
	Verifier         *auth.Verifier
}
type Server struct {
	cfg    Config
	mux    *http.ServeMux
	probe  *probe.HTTP
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(cfg Config) *Server {
	s := &Server{cfg: cfg, mux: http.NewServeMux(), probe: probe.NewHTTP(20 * time.Second)}
	s.routes()
	return s
}

func (s *Server) ListenAndServe() error {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.startSchedulers(ctx)
	return http.ListenAndServe(s.cfg.Addr, s.mux)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
	s.mux.HandleFunc("PUT /v1/admin/owners/{owner}/measurements/{id}", s.admin(s.putMeasurement))
	s.mux.HandleFunc("PUT /v1/admin/owners/{owner}/trust", s.admin(s.putTrust))
	s.mux.HandleFunc("POST /v1/admin/owners/{owner}/measurements/{id}/run", s.admin(s.runMeasurement))
	s.mux.HandleFunc("POST /v1/admin/owners/{owner}/measurements/{id}/batches", s.admin(s.putBatch))
	s.mux.HandleFunc("GET /v1/owners/{owner}/measurements", s.authorized("pulse:measurements:read", s.listMeasurements))
	s.mux.HandleFunc("GET /v1/owners/{owner}/measurements/{id}/report", s.authorized("pulse:reports:read", s.getReport))
}

func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminToken == "" || bearer(r) != s.cfg.AdminToken {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (s *Server) authorized(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Verifier == nil {
			writeJSON(w, 503, map[string]string{"error": "federated auth is not configured"})
			return
		}
		raw := bearer(r)
		if raw == "" {
			writeJSON(w, 401, map[string]string{"error": "missing bearer token"})
			return
		}
		claims, err := s.cfg.Verifier.Verify(r.Context(), raw)
		if err != nil {
			writeJSON(w, 401, map[string]string{"error": err.Error()})
			return
		}
		owner, id := r.PathValue("owner"), r.PathValue("id")
		bindings, err := s.cfg.Store.GetTrust(owner)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if id == "" {
			// Listing is permitted when at least one measurement in the owner is reachable.
			measurements, _ := s.cfg.Store.ListMeasurements(owner)
			allowed := false
			for _, m := range measurements {
				if auth.Authorize(claims, owner, m.ID, scope, bindings) == nil {
					allowed = true
					break
				}
			}
			if !allowed {
				writeJSON(w, 403, map[string]string{"error": "forbidden"})
				return
			}
		} else if err := auth.Authorize(claims, owner, id, scope, bindings); err != nil {
			writeJSON(w, 403, map[string]string{"error": err.Error()})
			return
		}
		next(w, r)
	}
}

func bearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if strings.HasPrefix(v, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))
	}
	return ""
}
func decode(r *http.Request, dst any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 16*1024*1024)).Decode(dst)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) putMeasurement(w http.ResponseWriter, r *http.Request) {
	var m model.Measurement
	if err := decode(r, &m); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	m.Owner = r.PathValue("owner")
	m.ID = r.PathValue("id")
	if err := s.cfg.Store.PutMeasurement(m); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, m)
}
func (s *Server) putTrust(w http.ResponseWriter, r *http.Request) {
	var b []model.TrustBinding
	if err := decode(r, &b); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := s.cfg.Store.PutTrust(r.PathValue("owner"), b); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "bindings": len(b)})
}
func (s *Server) putBatch(w http.ResponseWriter, r *http.Request) {
	var b model.Batch
	if err := decode(r, &b); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := s.cfg.Store.PutBatch(r.PathValue("owner"), r.PathValue("id"), b); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 201, b)
}
func (s *Server) runMeasurement(w http.ResponseWriter, r *http.Request) {
	obs, err := s.measure(r.Context(), r.PathValue("owner"), r.PathValue("id"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"observations": obs})
}
func (s *Server) listMeasurements(w http.ResponseWriter, r *http.Request) {
	ms, err := s.cfg.Store.ListMeasurements(r.PathValue("owner"))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"measurements": ms})
}

func (s *Server) getReport(w http.ResponseWriter, r *http.Request) {
	to := time.Now().UTC()
	from := to.Add(-7 * 24 * time.Hour)
	if raw := r.URL.Query().Get("from"); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			from = t
		}
	}
	if raw := r.URL.Query().Get("to"); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			to = t
		}
	}
	obs, err := s.cfg.Store.Observations(r.PathValue("owner"), r.PathValue("id"), from, to)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	batch, _ := s.cfg.Store.LatestBatch(r.PathValue("owner"), r.PathValue("id"), to)
	writeJSON(w, 200, report.Build(r.PathValue("owner"), r.PathValue("id"), from, to, obs, batch))
}

func (s *Server) measure(ctx context.Context, owner, id string) ([]model.Observation, error) {
	m, err := s.cfg.Store.GetMeasurement(owner, id)
	if err != nil {
		return nil, err
	}
	obs := make([]model.Observation, 0, len(m.Targets))
	for _, target := range m.Targets {
		o := s.probe.Measure(ctx, target)
		if err := s.cfg.Store.AppendObservation(owner, id, o); err != nil {
			return obs, err
		}
		obs = append(obs, o)
	}
	return obs, nil
}

func (s *Server) startSchedulers(ctx context.Context) {
	// Discover configured owners from a small explicit env list. This keeps v1's
	// scheduler deterministic; management writes can trigger runs immediately.
	for _, owner := range strings.Split(getenv("PULSE_OWNERS", ""), ",") {
		owner = strings.TrimSpace(owner)
		if owner == "" {
			continue
		}
		ms, err := s.cfg.Store.ListMeasurements(owner)
		if err != nil {
			log.Printf("scheduler owner %s: %v", owner, err)
			continue
		}
		for _, m := range ms {
			if !m.Enabled {
				continue
			}
			measurement := m
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				interval := time.Duration(measurement.IntervalSeconds) * time.Second
				if interval < time.Minute {
					interval = time.Minute
				}
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						if _, err := s.measure(ctx, measurement.Owner, measurement.ID); err != nil {
							log.Printf("measurement %s/%s: %v", measurement.Owner, measurement.ID, err)
						}
					}
				}
			}()
		}
	}
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func (s *Server) String() string { return fmt.Sprintf("pulse server %s", s.cfg.Addr) }
