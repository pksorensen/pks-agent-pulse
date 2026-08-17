package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Client struct {
	BaseURL, AdminToken string
	HTTP                *http.Client
}

func New(baseURL, adminToken string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), AdminToken: adminToken, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) DoJSON(ctx context.Context, method, path, token string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("pulse returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) WorkloadToken(ctx context.Context, scope string) (string, error) {
	if token := os.Getenv("PULSE_TOKEN"); token != "" {
		return token, nil
	}
	agentics := strings.TrimRight(os.Getenv("AGENTICS_BASE_URL"), "/")
	runnerToken := os.Getenv("AGENTICS_TOKEN")
	jobID := os.Getenv("AGENTICS_JOB_ID")
	owner := os.Getenv("AGENTICS_OWNER")
	project := os.Getenv("AGENTICS_PROJECT_NAME")
	if agentics == "" || runnerToken == "" || jobID == "" || owner == "" || project == "" {
		return "", fmt.Errorf("PULSE_TOKEN is unset and Agentics job identity is incomplete")
	}
	audience := os.Getenv("PULSE_AUDIENCE")
	if audience == "" {
		audience = c.BaseURL
	}
	body := map[string]any{"audience": audience, "scope": []string{scope}, "jobId": jobID}
	b, _ := json.Marshal(body)
	endpoint := fmt.Sprintf("%s/api/owners/%s/projects/%s/federation/token", agentics, url.PathEscape(owner), url.PathEscape(project))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+runnerToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return "", fmt.Errorf("Agentics token exchange returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("Agentics token exchange returned no access_token")
	}
	return result.AccessToken, nil
}
