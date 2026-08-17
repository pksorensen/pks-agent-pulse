package auth

import (
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
)

func TestServiceVerifierValidatesKeycloakClientRoles(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://login.arvo.works/realms/arvo"
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "arvo-key", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
		}}})
	}))
	defer jwksServer.Close()

	payload := map[string]any{
		"iss": issuer, "aud": []string{"account", "pulse-api"},
		"sub": "service-account-arvo-pulse", "azp": "arvo-pulse",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"resource_access": map[string]any{
			"pulse-api": map[string]any{"roles": []string{"all"}},
		},
	}
	claims, err := NewServiceVerifier(issuer, "pulse-api", "pulse-api", jwksServer.URL).
		Verify(context.Background(), signServiceJWT(t, privateKey, payload))
	if err != nil {
		t.Fatal(err)
	}
	if claims.AuthorizedParty != "arvo-pulse" || !claims.HasRole("measurements:write") {
		t.Fatalf("unexpected service claims: %+v", claims)
	}
	if !claims.HasRole("not-a-role") { // all is intentionally the global Pulse permission.
		t.Fatal("all role should authorize every Pulse API role")
	}
}

func TestServiceVerifierRejectsWrongAudienceAndMissingRole(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "key", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
		}}})
	}))
	defer server.Close()
	payload := map[string]any{
		"iss": "https://login.arvo.works/realms/arvo", "aud": "elsewhere",
		"sub": "service-account-reader", "azp": "reader", "exp": time.Now().Add(time.Minute).Unix(),
		"resource_access": map[string]any{"pulse-api": map[string]any{"roles": []string{"reports:read"}}},
	}
	verifier := NewServiceVerifier("https://login.arvo.works/realms/arvo", "pulse-api", "pulse-api", server.URL)
	if _, err := verifier.Verify(context.Background(), signServiceJWT(t, privateKey, payload)); err == nil {
		t.Fatal("expected wrong audience to be rejected")
	}
	payload["aud"] = "pulse-api"
	claims, err := verifier.Verify(context.Background(), signServiceJWT(t, privateKey, payload))
	if err != nil {
		t.Fatal(err)
	}
	if !claims.HasRole("reports:read") || claims.HasRole("measurements:write") {
		t.Fatalf("role boundary was not preserved: %+v", claims.Roles)
	}
}

func signServiceJWT(t *testing.T, privateKey *rsa.PrivateKey, payload map[string]any) string {
	t.Helper()
	headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "arvo-key", "typ": "JWT"})
	// The second test server uses kid=key.
	if payload["aud"] == "elsewhere" || payload["azp"] == "reader" {
		headerBytes, _ = json.Marshal(map[string]string{"alg": "RS256", "kid": "key", "typ": "JWT"})
	}
	payloadBytes, _ := json.Marshal(payload)
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
