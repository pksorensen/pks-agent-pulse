package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pksorensen/pks-agent-pulse/internal/model"
)

func Build(owner, measurementID string, from, to time.Time, observations []model.Observation, batch *model.Batch) model.Report {
	r := model.Report{Owner: owner, MeasurementID: measurementID, From: from.UTC().Format(time.RFC3339), To: to.UTC().Format(time.RFC3339), GeneratedAt: time.Now().UTC().Format(time.RFC3339), Samples: len(observations), StatusCounts: map[string]int{}, DataQuality: []string{}}
	var successful int
	var ttfb []int64
	affected := map[string]bool{}
	var slow []model.SlowTarget
	for _, o := range observations {
		key := "error"
		if o.Status > 0 {
			key = strconv.Itoa(o.Status)
		}
		r.StatusCounts[key]++
		if o.Error != "" || o.Status == 0 {
			r.Timeouts++
			affected[o.URL] = true
		} else if o.Status >= 500 {
			r.ServerErrors++
			affected[o.URL] = true
		} else if o.Status < 400 {
			successful++
		}
		if o.TTFBMs > 0 {
			ttfb = append(ttfb, o.TTFBMs)
			slow = append(slow, model.SlowTarget{URL: o.URL, TTFBMs: o.TTFBMs})
		}
		switch o.Cache {
		case "hit":
			r.CacheHits++
		case "miss":
			r.CacheMisses++
		default:
			r.CacheUnknown++
		}
	}
	if len(observations) > 0 {
		r.AvailabilityPct = float64(successful) * 100 / float64(len(observations))
	}
	sort.Slice(ttfb, func(i, j int) bool { return ttfb[i] < ttfb[j] })
	if len(ttfb) > 0 {
		r.TTFBMedianMs = percentile(ttfb, 0.5)
		r.TTFBP90Ms = percentile(ttfb, 0.9)
	}
	for u := range affected {
		r.AffectedURLs = append(r.AffectedURLs, u)
	}
	sort.Strings(r.AffectedURLs)
	sort.Slice(slow, func(i, j int) bool { return slow[i].TTFBMs > slow[j].TTFBMs })
	if len(slow) > 10 {
		slow = slow[:10]
	}
	r.Slowest = slow
	if batch != nil {
		observed := len(batch.Observations)
		quality := &model.BatchQuality{ID: batch.ID, Source: batch.Source, ExpectedCount: batch.ExpectedCount, ObservedCount: observed, MissingCount: max(0, batch.ExpectedCount-observed)}
		if batch.ExpectedCount > 0 {
			quality.CoveragePct = float64(observed) * 100 / float64(batch.ExpectedCount)
		}
		r.LatestBatch = quality
		if quality.CoveragePct < 100 {
			r.DataQuality = append(r.DataQuality, fmt.Sprintf("Latest %s batch covered %d/%d targets; lower issue counts may be measurement artefacts.", batch.Source, observed, batch.ExpectedCount))
		}
	}
	r.ExecutiveSummary = summary(r)
	return r
}

func percentile(sorted []int64, p float64) int64 {
	i := int(float64(len(sorted)-1)*p + 0.5)
	return sorted[i]
}

func summary(r model.Report) string {
	parts := []string{fmt.Sprintf("Availability %.2f%% across %d samples", r.AvailabilityPct, r.Samples)}
	if r.ServerErrors > 0 || r.Timeouts > 0 {
		parts = append(parts, fmt.Sprintf("%d server errors and %d timeouts", r.ServerErrors, r.Timeouts))
	}
	if r.TTFBMedianMs > 0 {
		parts = append(parts, fmt.Sprintf("TTFB median %d ms, p90 %d ms", r.TTFBMedianMs, r.TTFBP90Ms))
	}
	if r.CacheHits+r.CacheMisses > 0 {
		parts = append(parts, fmt.Sprintf("cache %d hit / %d miss", r.CacheHits, r.CacheMisses))
	}
	if len(r.DataQuality) > 0 {
		parts = append(parts, "data quality warning: "+r.DataQuality[0])
	}
	return strings.Join(parts, ". ") + "."
}
