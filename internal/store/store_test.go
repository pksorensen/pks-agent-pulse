package store

import (
	"testing"
	"time"

	"github.com/pksorensen/pks-agent-pulse/internal/model"
)

func TestMeasurementValidationAndObservationWindow(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bad := model.Measurement{Owner: "museliving", ID: "website", Name: "Website", Targets: []model.Target{{ID: "metadata", URL: "http://169.254.169.254/latest/meta-data"}}}
	if err := s.PutMeasurement(bad); err == nil {
		t.Fatal("expected private target URL to be rejected")
	}

	good := model.Measurement{Owner: "museliving", ID: "website", Name: "Website", Enabled: true, Targets: []model.Target{{ID: "home", URL: "https://museliving.dk/"}}}
	if err := s.PutMeasurement(good); err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetMeasurement("museliving", "website")
	if err != nil || stored.IntervalSeconds != 900 {
		t.Fatalf("default interval was not persisted: %#v %v", stored, err)
	}

	base := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	for i := -1; i <= 1; i++ {
		if err := s.AppendObservation("museliving", "website", model.Observation{TimestampMs: base.Add(time.Duration(i) * time.Hour).UnixMilli(), URL: "https://museliving.dk/", Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Observations("museliving", "website", base, base.Add(2*time.Hour))
	if err != nil || len(got) != 2 {
		t.Fatalf("expected inclusive-from/exclusive-to window with 2 rows, got %d: %v", len(got), err)
	}
}

func TestBatchPersistsCoverageAndObservations(t *testing.T) {
	s, _ := New(t.TempDir())
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	b := model.Batch{ID: "seo-20260817", Source: "seo-scan", TimestampMs: now.UnixMilli(), ExpectedCount: 2, Observations: []model.Observation{{URL: "https://museliving.dk/", Status: 200}}}
	if err := s.PutBatch("museliving", "website", b); err != nil {
		t.Fatal(err)
	}
	latest, err := s.LatestBatch("museliving", "website", now.Add(time.Second))
	if err != nil || latest == nil || latest.ID != b.ID || latest.Observations[0].BatchID != b.ID {
		t.Fatalf("unexpected stored batch: %#v %v", latest, err)
	}
}
