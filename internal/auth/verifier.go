package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pksorensen/pks-agent-pulse/internal/model"
)

type jwk struct{ Kty, Crv, Kid, X, Alg string }
type jwks struct {
	Keys []jwk `json:"keys"`
}

type Verifier struct {
	issuer    string
	audience  string
	jwksURL   string
	client    *http.Client
	mu        sync.Mutex
	keys      map[string]ed25519.PublicKey
	fetchedAt time.Time
}

func NewVerifier(issuer, audience, jwksURL string) *Verifier {
	return &Verifier{issuer: strings.TrimRight(issuer, "/"), audience: audience, jwksURL: jwksURL, client: &http.Client{Timeout: 10 * time.Second}, keys: map[string]ed25519.PublicKey{}}
}

func (v *Verifier) Verify(ctx context.Context, raw string) (model.WorkloadClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return model.WorkloadClaims{}, errors.New("token is not a JWT")
	}
	var header struct{ Alg, Kid string }
	if err := decodeJSON(parts[0], &header); err != nil {
		return model.WorkloadClaims{}, err
	}
	if header.Alg != "EdDSA" || header.Kid == "" {
		return model.WorkloadClaims{}, errors.New("unsupported JWT header")
	}
	key, err := v.key(ctx, header.Kid)
	if err != nil {
		return model.WorkloadClaims{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return model.WorkloadClaims{}, errors.New("invalid JWT signature")
	}
	var payload struct {
		Iss            string `json:"iss"`
		Aud            any    `json:"aud"`
		Sub            string `json:"sub"`
		Exp            int64  `json:"exp"`
		Nbf            int64  `json:"nbf"`
		Owner          string `json:"owner"`
		Project        string `json:"project"`
		AssemblyLineID string `json:"assembly_line_id"`
		StationID      string `json:"station_id"`
		TaskID         string `json:"task_id"`
		JobID          string `json:"job_id"`
		RunID          string `json:"run_id"`
		Scope          string `json:"scope"`
	}
	if err := decodeJSON(parts[1], &payload); err != nil {
		return model.WorkloadClaims{}, err
	}
	now := time.Now()
	if strings.TrimRight(payload.Iss, "/") != v.issuer {
		return model.WorkloadClaims{}, fmt.Errorf("unexpected issuer %q", payload.Iss)
	}
	aud := audiences(payload.Aud)
	if !contains(aud, v.audience) {
		return model.WorkloadClaims{}, errors.New("unexpected audience")
	}
	if payload.Exp == 0 || now.After(time.Unix(payload.Exp, 0).Add(30*time.Second)) {
		return model.WorkloadClaims{}, errors.New("token expired")
	}
	if payload.Nbf > 0 && now.Add(30*time.Second).Before(time.Unix(payload.Nbf, 0)) {
		return model.WorkloadClaims{}, errors.New("token not active")
	}
	return model.WorkloadClaims{Issuer: payload.Iss, Audience: aud, Subject: payload.Sub, ExpiresAt: time.Unix(payload.Exp, 0), Owner: payload.Owner, Project: payload.Project, AssemblyLineID: payload.AssemblyLineID, StationID: payload.StationID, TaskID: payload.TaskID, JobID: payload.JobID, RunID: payload.RunID, Scopes: strings.Fields(payload.Scope)}, nil
}

func decodeJSON(encoded string, dst any) error {
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func audiences(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func contains(values []string, wanted string) bool {
	for _, v := range values {
		if v == wanted {
			return true
		}
	}
	return false
}

func (v *Verifier) key(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if key := v.keys[kid]; key != nil && time.Since(v.fetchedAt) < 6*time.Hour {
		return key, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("JWKS returned %d: %s", resp.StatusCode, b)
	}
	var set jwks
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	keys := map[string]ed25519.PublicKey{}
	for _, item := range set.Keys {
		if item.Kty != "OKP" || item.Crv != "Ed25519" || item.Alg != "EdDSA" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(item.X)
		if err == nil && len(raw) == ed25519.PublicKeySize {
			keys[item.Kid] = ed25519.PublicKey(raw)
		}
	}
	v.keys, v.fetchedAt = keys, time.Now()
	if key := keys[kid]; key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
}

func Authorize(claims model.WorkloadClaims, owner, measurementID, requiredScope string, bindings []model.TrustBinding) error {
	if !contains(claims.Scopes, requiredScope) {
		return errors.New("token lacks required scope")
	}
	for _, b := range bindings {
		if strings.TrimRight(b.Issuer, "/") != strings.TrimRight(claims.Issuer, "/") || b.ProjectOwner != claims.Owner || b.Project != claims.Project {
			continue
		}
		if !contains(b.AssemblyLineIDs, claims.AssemblyLineID) || !contains(b.MeasurementIDs, measurementID) || !contains(b.Scopes, requiredScope) {
			continue
		}
		if len(b.StationIDs) > 0 && !contains(b.StationIDs, claims.StationID) {
			continue
		}
		return nil
	}
	return fmt.Errorf("workload is not trusted for owner %s measurement %s", owner, measurementID)
}
