package report

import (
	"strings"
	"testing"
	"time"

	"github.com/pksorensen/pks-agent-pulse/internal/model"
)

func TestBuildFlagsCoverageArtefactsAndAggregatesWebHealth(t *testing.T) {
	from := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	to := from.Add(7 * 24 * time.Hour)
	observations := []model.Observation{
		{URL: "https://example.com/", Status: 200, TTFBMs: 100, Cache: "hit"},
		{URL: "https://example.com/category", Status: 200, TTFBMs: 2000, Cache: "miss"},
		{URL: "https://example.com/product", Status: 504, TTFBMs: 400, Cache: "unknown"},
		{URL: "https://example.com/blog", Error: "context deadline exceeded"},
	}
	batch := &model.Batch{ID: "scan-1", Source: "seo-scan", ExpectedCount: 62, Observations: make([]model.Observation, 53)}

	r := Build("museliving", "website", from, to, observations, batch)

	if r.Samples != 4 || r.AvailabilityPct != 50 {
		t.Fatalf("unexpected availability: samples=%d percentage=%f", r.Samples, r.AvailabilityPct)
	}
	if r.ServerErrors != 1 || r.Timeouts != 1 {
		t.Fatalf("unexpected failures: server=%d timeout=%d", r.ServerErrors, r.Timeouts)
	}
	if r.TTFBMedianMs != 400 || r.TTFBP90Ms != 2000 {
		t.Fatalf("unexpected percentiles: median=%d p90=%d", r.TTFBMedianMs, r.TTFBP90Ms)
	}
	if r.LatestBatch == nil || r.LatestBatch.MissingCount != 9 || r.LatestBatch.CoveragePct < 85 || r.LatestBatch.CoveragePct > 86 {
		t.Fatalf("unexpected batch quality: %#v", r.LatestBatch)
	}
	if len(r.DataQuality) != 1 || !strings.Contains(r.DataQuality[0], "measurement artefacts") {
		t.Fatalf("expected explicit artefact warning, got %#v", r.DataQuality)
	}
}
