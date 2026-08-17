package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pksorensen/pks-agent-pulse/internal/auth"
	"github.com/pksorensen/pks-agent-pulse/internal/store"
)

func TestServiceClientAllRoleCanManageAndReadMeasurements(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := serviceJWKS(t, privateKey)
	defer jwks.Close()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{
		Store: st,
		ServiceVerifier: auth.NewServiceVerifier(
			"https://login.arvo.works/realms/arvo", "pulse-api", "pulse-api", jwks.URL,
		),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startSchedulers(ctx)
	api := httptest.NewServer(s)
	defer api.Close()
	token := serviceToken(t, privateKey, []string{"all"})

	body := []byte(`{"name":"Museliving website","enabled":true,"intervalSeconds":900,"targets":[{"id":"home","kind":"home","url":"https://museliving.dk/"}]}`)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, api.URL+"/v1/admin/owners/museliving/measurements/website", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("put measurement returned %d", response.StatusCode)
	}
	s.schedulerMu.Lock()
	_, scheduled := s.schedulers["museliving/website"]
	s.schedulerMu.Unlock()
	if !scheduled {
		t.Fatal("enabled measurement created through the API was not scheduled")
	}

	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, api.URL+"/v1/owners/museliving/measurements", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	response, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list measurements returned %d", response.StatusCode)
	}
}

func TestServiceClientRoleBoundaryIsEnforced(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := serviceJWKS(t, privateKey)
	defer jwks.Close()
	st, _ := store.New(t.TempDir())
	api := httptest.NewServer(New(Config{
		Store: st,
		ServiceVerifier: auth.NewServiceVerifier(
			"https://login.arvo.works/realms/arvo", "pulse-api", "pulse-api", jwks.URL,
		),
	}))
	defer api.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, api.URL+"/v1/admin/owners/museliving/measurements/website", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+serviceToken(t, privateKey, []string{"reports:read"}))
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for read-only client, got %d", response.StatusCode)
	}
}

func serviceJWKS(t *testing.T, privateKey *rsa.PrivateKey) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "key", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
		}}})
	}))
}

func serviceToken(t *testing.T, privateKey *rsa.PrivateKey, roles []string) string {
	t.Helper()
	headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "key", "typ": "JWT"})
	payloadBytes, _ := json.Marshal(map[string]any{
		"iss": "https://login.arvo.works/realms/arvo", "aud": "pulse-api",
		"sub": "service-account-arvo-pulse", "azp": "arvo-pulse",
		"exp":             time.Now().Add(5 * time.Minute).Unix(),
		"resource_access": map[string]any{"pulse-api": map[string]any{"roles": roles}},
	})
	header := base64.RawURLEncoding.EncodeToString(headerBytes)
	body := base64.RawURLEncoding.EncodeToString(payloadBytes)
	input := header + "." + body
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}
