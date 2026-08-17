package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"github.com/pksorensen/pks-agent-pulse/internal/model"
)

type HTTP struct{ client *http.Client }

func NewHTTP(timeout time.Duration) *HTTP {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if !publicIP(ip) {
				return nil, fmt.Errorf("target %s resolved to a private or local address", host)
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
	}
	return &HTTP{client: &http.Client{Timeout: timeout, Transport: transport}}
}

func publicIP(ip net.IP) bool {
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && !ip.IsMulticast()
}

func (p *HTTP) Measure(ctx context.Context, target model.Target) model.Observation {
	start := time.Now()
	o := model.Observation{TimestampMs: start.UnixMilli(), Source: "pulse", TargetID: target.ID, TargetKind: target.Kind, URL: target.URL}
	var dnsStart, connectStart, tlsStart time.Time
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				o.DNSMs = time.Since(dnsStart).Milliseconds()
			}
		},
		ConnectStart: func(_, _ string) { connectStart = time.Now() },
		ConnectDone: func(_, _ string, _ error) {
			if !connectStart.IsZero() {
				o.ConnectMs = time.Since(connectStart).Milliseconds()
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			if !tlsStart.IsZero() {
				o.TLSMs = time.Since(tlsStart).Milliseconds()
			}
		},
		GotFirstResponseByte: func() { o.TTFBMs = time.Since(start).Milliseconds() },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, target.URL, nil)
	if err != nil {
		o.Error = err.Error()
		return o
	}
	req.Header.Set("User-Agent", "Kanariefugl-Pulse/0.1 (+https://agentics.dk)")
	resp, err := p.client.Do(req)
	if err != nil {
		o.Error = err.Error()
		o.TotalMs = time.Since(start).Milliseconds()
		return o
	}
	defer resp.Body.Close()
	o.Status = resp.StatusCode
	o.FinalURL = resp.Request.URL.String()
	n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 8*1024*1024))
	o.Bytes = n
	o.TotalMs = time.Since(start).Milliseconds()
	if readErr != nil {
		o.Error = readErr.Error()
	}
	o.Headers = selectedHeaders(resp.Header)
	o.Cache = cacheStatus(resp.Header)
	return o
}

func selectedHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for _, name := range []string{"X-LiteSpeed-Cache", "X-Cache", "CF-Cache-Status", "Age", "Server", "Cache-Control"} {
		if v := h.Get(name); v != "" {
			out[name] = v
		}
	}
	return out
}

func cacheStatus(h http.Header) string {
	for _, name := range []string{"X-LiteSpeed-Cache", "X-Cache", "CF-Cache-Status"} {
		v := strings.ToLower(h.Get(name))
		if strings.Contains(v, "hit") {
			return "hit"
		}
		if strings.Contains(v, "miss") || strings.Contains(v, "bypass") || strings.Contains(v, "dynamic") {
			return "miss"
		}
	}
	return "unknown"
}
