package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pksorensen/pks-agent-pulse/internal/model"
)

var safeSegment = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type Store struct{ root string }

func New(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("data directory is required")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &Store{root: root}, nil
}

func checkSegment(v, label string) error {
	if !safeSegment.MatchString(v) {
		return fmt.Errorf("invalid %s %q", label, v)
	}
	return nil
}

func (s *Store) measurementDir(owner, id string) (string, error) {
	if err := checkSegment(owner, "owner"); err != nil {
		return "", err
	}
	if err := checkSegment(id, "measurement id"); err != nil {
		return "", err
	}
	return filepath.Join(s.root, "owners", owner, "measurements", id), nil
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, value any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, value)
}

func (s *Store) PutMeasurement(m model.Measurement) error {
	dir, err := s.measurementDir(m.Owner, m.ID)
	if err != nil {
		return err
	}
	if m.IntervalSeconds <= 0 {
		m.IntervalSeconds = 900
	}
	if m.Name == "" {
		return errors.New("measurement name is required")
	}
	if len(m.Targets) == 0 {
		return errors.New("at least one target is required")
	}
	seen := map[string]bool{}
	for _, target := range m.Targets {
		if err := checkSegment(target.ID, "target id"); err != nil {
			return err
		}
		if seen[target.ID] {
			return fmt.Errorf("duplicate target id %q", target.ID)
		}
		seen[target.ID] = true
		if err := validatePublicHTTPURL(target.URL); err != nil {
			return fmt.Errorf("target %s: %w", target.ID, err)
		}
	}
	return writeJSON(filepath.Join(dir, "measurement.json"), m)
}

func validatePublicHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("URL must be an absolute http or https URL")
	}
	if u.User != nil {
		return errors.New("URL must not contain user information")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return errors.New("localhost targets are not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && !isPublicIP(ip) {
		return errors.New("private or local IP targets are not allowed")
	}
	return nil
}

func isPublicIP(ip net.IP) bool {
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && !ip.IsMulticast()
}

func (s *Store) GetMeasurement(owner, id string) (model.Measurement, error) {
	dir, err := s.measurementDir(owner, id)
	if err != nil {
		return model.Measurement{}, err
	}
	var m model.Measurement
	err = readJSON(filepath.Join(dir, "measurement.json"), &m)
	return m, err
}

func (s *Store) ListMeasurements(owner string) ([]model.Measurement, error) {
	if err := checkSegment(owner, "owner"); err != nil {
		return nil, err
	}
	root := filepath.Join(s.root, "owners", owner, "measurements")
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return []model.Measurement{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]model.Measurement, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m, err := s.GetMeasurement(owner, e.Name())
		if err == nil {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) AppendObservation(owner, id string, o model.Observation) error {
	dir, err := s.measurementDir(owner, id)
	if err != nil {
		return err
	}
	if o.TimestampMs == 0 {
		o.TimestampMs = time.Now().UnixMilli()
	}
	day := time.UnixMilli(o.TimestampMs).UTC().Format("2006-01-02")
	path := filepath.Join(dir, "observations", day+".jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

func (s *Store) PutBatch(owner, id string, batch model.Batch) error {
	dir, err := s.measurementDir(owner, id)
	if err != nil {
		return err
	}
	if batch.TimestampMs == 0 {
		batch.TimestampMs = time.Now().UnixMilli()
	}
	if batch.ID == "" {
		batch.ID = fmt.Sprintf("%d", batch.TimestampMs)
	}
	for i := range batch.Observations {
		batch.Observations[i].BatchID = batch.ID
		if batch.Observations[i].Source == "" {
			batch.Observations[i].Source = batch.Source
		}
		if batch.Observations[i].TimestampMs == 0 {
			batch.Observations[i].TimestampMs = batch.TimestampMs
		}
		if err := s.AppendObservation(owner, id, batch.Observations[i]); err != nil {
			return err
		}
	}
	return writeJSON(filepath.Join(dir, "batches", batch.ID+".json"), batch)
}

func (s *Store) LatestBatch(owner, id string, before time.Time) (*model.Batch, error) {
	dir, err := s.measurementDir(owner, id)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(dir, "batches")
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var latest *model.Batch
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		var b model.Batch
		if readJSON(filepath.Join(root, e.Name()), &b) != nil {
			continue
		}
		if time.UnixMilli(b.TimestampMs).After(before) {
			continue
		}
		if latest == nil || b.TimestampMs > latest.TimestampMs {
			copy := b
			latest = &copy
		}
	}
	return latest, nil
}

func (s *Store) Observations(owner, id string, from, to time.Time) ([]model.Observation, error) {
	dir, err := s.measurementDir(owner, id)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(dir, "observations")
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return []model.Observation{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out []model.Observation
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".jsonl" {
			continue
		}
		f, err := os.Open(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			var o model.Observation
			if json.Unmarshal(scanner.Bytes(), &o) != nil {
				continue
			}
			t := time.UnixMilli(o.TimestampMs)
			if !t.Before(from) && t.Before(to) {
				out = append(out, o)
			}
		}
		f.Close()
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TimestampMs < out[j].TimestampMs })
	return out, nil
}

func (s *Store) PutTrust(owner string, bindings []model.TrustBinding) error {
	if err := checkSegment(owner, "owner"); err != nil {
		return err
	}
	return writeJSON(filepath.Join(s.root, "owners", owner, "trust.json"), bindings)
}

func (s *Store) GetTrust(owner string) ([]model.TrustBinding, error) {
	if err := checkSegment(owner, "owner"); err != nil {
		return nil, err
	}
	var bindings []model.TrustBinding
	err := readJSON(filepath.Join(s.root, "owners", owner, "trust.json"), &bindings)
	if os.IsNotExist(err) {
		return []model.TrustBinding{}, nil
	}
	return bindings, err
}
