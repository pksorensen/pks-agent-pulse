package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type serviceJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type serviceJWKS struct {
	Keys []serviceJWK `json:"keys"`
}

// ServiceClaims are the Keycloak client-credentials claims Pulse authorizes.
// Roles are client roles under roleClient, normally pulse-api.
type ServiceClaims struct {
	Subject         string
	AuthorizedParty string
	Roles           []string
}

func (c ServiceClaims) HasRole(role string) bool {
	return contains(c.Roles, "all") || contains(c.Roles, role)
}

// ServiceVerifier validates RS256 access tokens from the Keycloak realm used by
// Arvo. It is deliberately separate from Verifier: the latter accepts Agentics
// EdDSA workload tokens and applies per-owner trust bindings, while this one is
// for durable service clients with explicit Pulse API roles.
type ServiceVerifier struct {
	issuer     string
	audience   string
	roleClient string
	jwksURL    string
	client     *http.Client
	mu         sync.Mutex
	keys       map[string]*rsa.PublicKey
	fetchedAt  time.Time
}

func NewServiceVerifier(issuer, audience, roleClient, jwksURL string) *ServiceVerifier {
	issuer = strings.TrimRight(issuer, "/")
	if roleClient == "" {
		roleClient = audience
	}
	if jwksURL == "" {
		jwksURL = issuer + "/protocol/openid-connect/certs"
	}
	return &ServiceVerifier{
		issuer: issuer, audience: audience, roleClient: roleClient, jwksURL: jwksURL,
		client: &http.Client{Timeout: 10 * time.Second}, keys: map[string]*rsa.PublicKey{},
	}
}

func (v *ServiceVerifier) Verify(ctx context.Context, raw string) (ServiceClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ServiceClaims{}, errors.New("token is not a JWT")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeJSON(parts[0], &header); err != nil {
		return ServiceClaims{}, err
	}
	if header.Alg != "RS256" || header.Kid == "" {
		return ServiceClaims{}, errors.New("token is not a Keycloak RS256 access token")
	}
	key, err := v.key(ctx, header.Kid)
	if err != nil {
		return ServiceClaims{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ServiceClaims{}, errors.New("invalid JWT signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return ServiceClaims{}, errors.New("invalid JWT signature")
	}

	var payload struct {
		Issuer          string `json:"iss"`
		Audience        any    `json:"aud"`
		Subject         string `json:"sub"`
		AuthorizedParty string `json:"azp"`
		ExpiresAt       int64  `json:"exp"`
		NotBefore       int64  `json:"nbf"`
		ResourceAccess  map[string]struct {
			Roles []string `json:"roles"`
		} `json:"resource_access"`
	}
	if err := decodeJSON(parts[1], &payload); err != nil {
		return ServiceClaims{}, err
	}
	now := time.Now()
	if strings.TrimRight(payload.Issuer, "/") != v.issuer {
		return ServiceClaims{}, fmt.Errorf("unexpected issuer %q", payload.Issuer)
	}
	if !contains(audiences(payload.Audience), v.audience) {
		return ServiceClaims{}, errors.New("unexpected audience")
	}
	if payload.ExpiresAt == 0 || now.After(time.Unix(payload.ExpiresAt, 0).Add(30*time.Second)) {
		return ServiceClaims{}, errors.New("token expired")
	}
	if payload.NotBefore > 0 && now.Add(30*time.Second).Before(time.Unix(payload.NotBefore, 0)) {
		return ServiceClaims{}, errors.New("token not active")
	}
	if payload.Subject == "" || payload.AuthorizedParty == "" {
		return ServiceClaims{}, errors.New("service token is missing sub or azp")
	}
	return ServiceClaims{
		Subject: payload.Subject, AuthorizedParty: payload.AuthorizedParty,
		Roles: payload.ResourceAccess[v.roleClient].Roles,
	}, nil
}

func (v *ServiceVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("service JWKS returned %d: %s", resp.StatusCode, body)
	}
	var set serviceJWKS
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, item := range set.Keys {
		if item.Kty != "RSA" || item.Alg != "RS256" || item.Kid == "" {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(item.N)
		e, errE := base64.RawURLEncoding.DecodeString(item.E)
		if errN != nil || errE != nil || len(n) == 0 || len(e) == 0 {
			continue
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent<<8 | int(b)
		}
		if exponent < 3 {
			continue
		}
		keys[item.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
	}
	v.keys, v.fetchedAt = keys, time.Now()
	if key := keys[kid]; key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("unknown service signing key %q", kid)
}
