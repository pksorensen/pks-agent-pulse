package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pksorensen/pks-agent-pulse/internal/model"
)

func TestVerifierAndTrustBinding(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "kid": "test-key", "x": base64.RawURLEncoding.EncodeToString(publicKey), "alg": "EdDSA"}}})
	}))
	defer jwksServer.Close()

	issuer := "https://agentics.dk"
	audience := "https://pulse.agentics.dk"
	payload := map[string]any{
		"iss": issuer, "aud": audience, "sub": "runner-job:job-1", "exp": time.Now().Add(5 * time.Minute).Unix(),
		"owner": "pksorensen", "project": "museliving", "assembly_line_id": "seo-weekly", "station_id": "report",
		"task_id": "task-1", "job_id": "job-1", "run_id": "run-1", "scope": "pulse:reports:read",
	}
	raw := signTestJWT(t, privateKey, payload)
	claims, err := NewVerifier(issuer, audience, jwksServer.URL).Verify(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	binding := model.TrustBinding{Issuer: issuer, ProjectOwner: "pksorensen", Project: "museliving", AssemblyLineIDs: []string{"seo-weekly"}, StationIDs: []string{"report"}, MeasurementIDs: []string{"website"}, Scopes: []string{"pulse:reports:read"}}
	if err := Authorize(claims, "museliving", "website", "pulse:reports:read", []model.TrustBinding{binding}); err != nil {
		t.Fatal(err)
	}
	claims.StationID = "untrusted-station"
	if err := Authorize(claims, "museliving", "website", "pulse:reports:read", []model.TrustBinding{binding}); err == nil {
		t.Fatal("expected station mismatch to be denied")
	}
}

func TestVerifierRejectsWrongAudienceAndExpiredToken(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "kid": "test-key", "x": base64.RawURLEncoding.EncodeToString(publicKey), "alg": "EdDSA"}}})
	}))
	defer server.Close()
	base := map[string]any{"iss": "https://agentics.dk", "aud": "wrong", "exp": time.Now().Add(5 * time.Minute).Unix()}
	if _, err := NewVerifier("https://agentics.dk", "https://pulse.agentics.dk", server.URL).Verify(context.Background(), signTestJWT(t, privateKey, base)); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("expected audience rejection, got %v", err)
	}
	base["aud"] = "https://pulse.agentics.dk"
	base["exp"] = time.Now().Add(-time.Minute).Unix()
	if _, err := NewVerifier("https://agentics.dk", "https://pulse.agentics.dk", server.URL).Verify(context.Background(), signTestJWT(t, privateKey, base)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry rejection, got %v", err)
	}
}

func signTestJWT(t *testing.T, privateKey ed25519.PrivateKey, payload map[string]any) string {
	t.Helper()
	headerBytes, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": "test-key", "typ": "JWT"})
	payloadBytes, _ := json.Marshal(payload)
	header := base64.RawURLEncoding.EncodeToString(headerBytes)
	body := base64.RawURLEncoding.EncodeToString(payloadBytes)
	input := header + "." + body
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(input)))
}
