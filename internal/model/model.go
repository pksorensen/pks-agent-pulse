package model

import "time"

type Measurement struct {
	Owner           string   `json:"owner"`
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	IntervalSeconds int      `json:"intervalSeconds"`
	Targets         []Target `json:"targets"`
}

type Target struct {
	ID   string `json:"id"`
	URL  string `json:"url"`
	Kind string `json:"kind"`
}

type Observation struct {
	TimestampMs int64             `json:"timestampMs"`
	Source      string            `json:"source"`
	BatchID     string            `json:"batchId,omitempty"`
	TargetID    string            `json:"targetId"`
	TargetKind  string            `json:"targetKind,omitempty"`
	URL         string            `json:"url"`
	FinalURL    string            `json:"finalUrl,omitempty"`
	Status      int               `json:"status,omitempty"`
	Error       string            `json:"error,omitempty"`
	TTFBMs      int64             `json:"ttfbMs,omitempty"`
	TotalMs     int64             `json:"totalMs,omitempty"`
	DNSMs       int64             `json:"dnsMs,omitempty"`
	ConnectMs   int64             `json:"connectMs,omitempty"`
	TLSMs       int64             `json:"tlsMs,omitempty"`
	Bytes       int64             `json:"bytes,omitempty"`
	Cache       string            `json:"cache,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

type Batch struct {
	ID            string        `json:"id"`
	Source        string        `json:"source"`
	TimestampMs   int64         `json:"timestampMs"`
	ExpectedCount int           `json:"expectedCount"`
	Observations  []Observation `json:"observations"`
}

type TrustBinding struct {
	ID              string   `json:"id"`
	Issuer          string   `json:"issuer"`
	ProjectOwner    string   `json:"projectOwner"`
	Project         string   `json:"project"`
	AssemblyLineIDs []string `json:"assemblyLineIds"`
	StationIDs      []string `json:"stationIds,omitempty"`
	MeasurementIDs  []string `json:"measurementIds"`
	Scopes          []string `json:"scopes"`
}

type WorkloadClaims struct {
	Issuer         string
	Audience       []string
	Subject        string
	ExpiresAt      time.Time
	Owner          string
	Project        string
	AssemblyLineID string
	StationID      string
	TaskID         string
	JobID          string
	RunID          string
	Scopes         []string
}

type Report struct {
	Owner            string         `json:"owner"`
	MeasurementID    string         `json:"measurementId"`
	From             string         `json:"from"`
	To               string         `json:"to"`
	GeneratedAt      string         `json:"generatedAt"`
	Samples          int            `json:"samples"`
	AvailabilityPct  float64        `json:"availabilityPct"`
	StatusCounts     map[string]int `json:"statusCounts"`
	Timeouts         int            `json:"timeouts"`
	ServerErrors     int            `json:"serverErrors"`
	TTFBMedianMs     int64          `json:"ttfbMedianMs"`
	TTFBP90Ms        int64          `json:"ttfbP90Ms"`
	CacheHits        int            `json:"cacheHits"`
	CacheMisses      int            `json:"cacheMisses"`
	CacheUnknown     int            `json:"cacheUnknown"`
	AffectedURLs     []string       `json:"affectedUrls"`
	Slowest          []SlowTarget   `json:"slowest"`
	LatestBatch      *BatchQuality  `json:"latestBatch,omitempty"`
	DataQuality      []string       `json:"dataQuality"`
	ExecutiveSummary string         `json:"executiveSummary"`
}

type SlowTarget struct {
	URL    string `json:"url"`
	TTFBMs int64  `json:"ttfbMs"`
}

type BatchQuality struct {
	ID            string  `json:"id"`
	Source        string  `json:"source"`
	ExpectedCount int     `json:"expectedCount"`
	ObservedCount int     `json:"observedCount"`
	CoveragePct   float64 `json:"coveragePct"`
	MissingCount  int     `json:"missingCount"`
}
