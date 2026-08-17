package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pksorensen/pks-agent-pulse/internal/auth"
	"github.com/pksorensen/pks-agent-pulse/internal/client"
	"github.com/pksorensen/pks-agent-pulse/internal/model"
	"github.com/pksorensen/pks-agent-pulse/internal/server"
	"github.com/pksorensen/pks-agent-pulse/internal/store"
)

func Run(args []string, version string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		usage()
		return 0
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Println("pulse", version)
		return 0
	case "serve":
		return serve(args[1:])
	case "measurement":
		return measurement(args[1:])
	case "trust":
		return trust(args[1:])
	case "run":
		return runRemote(args[1:])
	case "report":
		return reportRemote(args[1:])
	case "ingest":
		return ingest(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "unknown command", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Print(`pulse — owner-scoped active measurements

Commands:
  pulse serve
  pulse measurement put --owner OWNER --id ID --file measurement.json
  pulse trust put --owner OWNER --file trust.json
  pulse run --owner OWNER --measurement ID
  pulse report --owner OWNER --measurement ID [--days 7]
  pulse ingest seo --owner OWNER --measurement ID --file pages.jsonl --expected N
`)
}

func remote() *client.Client {
	return client.New(env("PULSE_URL", "http://localhost:8090"), os.Getenv("PULSE_ADMIN_TOKEN"))
}

func serve(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", env("PULSE_ADDR", ":8090"), "")
	data := fs.String("data", env("USER_DATA_DIR", "/data"), "")
	if fs.Parse(args) != nil {
		return 2
	}
	st, err := store.New(*data)
	if err != nil {
		return fail(err)
	}
	var verifier *auth.Verifier
	issuer := os.Getenv("PULSE_WORKLOAD_ISSUER")
	aud := os.Getenv("PULSE_AUDIENCE")
	jwks := os.Getenv("PULSE_WORKLOAD_JWKS_URL")
	if issuer != "" && aud != "" && jwks != "" {
		verifier = auth.NewVerifier(issuer, aud, jwks)
	}
	s := server.New(server.Config{Addr: *addr, AdminToken: os.Getenv("PULSE_ADMIN_TOKEN"), Store: st, Verifier: verifier})
	fmt.Fprintf(os.Stderr, "pulse listening on %s (data=%s federation=%t)\n", *addr, *data, verifier != nil)
	return fail(s.ListenAndServe())
}

func measurement(args []string) int {
	if len(args) == 0 || args[0] != "put" {
		return fail(fmt.Errorf("usage: pulse measurement put ..."))
	}
	fs := flag.NewFlagSet("measurement put", flag.ContinueOnError)
	owner := fs.String("owner", "", "")
	id := fs.String("id", "", "")
	file := fs.String("file", "", "")
	if fs.Parse(args[1:]) != nil {
		return 2
	}
	var m model.Measurement
	if err := readJSON(*file, &m); err != nil {
		return fail(err)
	}
	var out any
	err := remote().DoJSON(context.Background(), "PUT", fmt.Sprintf("/v1/admin/owners/%s/measurements/%s", *owner, *id), os.Getenv("PULSE_ADMIN_TOKEN"), m, &out)
	if err != nil {
		return fail(err)
	}
	printJSON(out)
	return 0
}
func trust(args []string) int {
	if len(args) == 0 || args[0] != "put" {
		return fail(fmt.Errorf("usage: pulse trust put ..."))
	}
	fs := flag.NewFlagSet("trust put", flag.ContinueOnError)
	owner := fs.String("owner", "", "")
	file := fs.String("file", "", "")
	if fs.Parse(args[1:]) != nil {
		return 2
	}
	var b []model.TrustBinding
	if err := readJSON(*file, &b); err != nil {
		return fail(err)
	}
	var out any
	err := remote().DoJSON(context.Background(), "PUT", fmt.Sprintf("/v1/admin/owners/%s/trust", *owner), os.Getenv("PULSE_ADMIN_TOKEN"), b, &out)
	if err != nil {
		return fail(err)
	}
	printJSON(out)
	return 0
}
func runRemote(args []string) int {
	owner, id, _, ok := common(args, false)
	if !ok {
		return 2
	}
	var out any
	err := remote().DoJSON(context.Background(), "POST", fmt.Sprintf("/v1/admin/owners/%s/measurements/%s/run", owner, id), os.Getenv("PULSE_ADMIN_TOKEN"), nil, &out)
	if err != nil {
		return fail(err)
	}
	printJSON(out)
	return 0
}

func reportRemote(args []string) int {
	owner, id, days, ok := common(args, true)
	if !ok {
		return 2
	}
	c := remote()
	token, err := c.WorkloadToken(context.Background(), "pulse:reports:read")
	if err != nil {
		return fail(err)
	}
	to := time.Now().UTC()
	from := to.Add(-time.Duration(days) * 24 * time.Hour)
	path := fmt.Sprintf("/v1/owners/%s/measurements/%s/report?from=%s&to=%s", owner, id, from.Format(time.RFC3339), to.Format(time.RFC3339))
	var out model.Report
	if err := c.DoJSON(context.Background(), "GET", path, token, nil, &out); err != nil {
		return fail(err)
	}
	printJSON(out)
	return 0
}

func common(args []string, withDays bool) (string, string, int, bool) {
	fs := flag.NewFlagSet("common", flag.ContinueOnError)
	owner := fs.String("owner", "", "")
	id := fs.String("measurement", "", "")
	days := fs.Int("days", 7, "")
	if fs.Parse(args) != nil || *owner == "" || *id == "" {
		fmt.Fprintln(os.Stderr, "--owner and --measurement are required")
		return "", "", 0, false
	}
	if !withDays {
		*days = 0
	}
	return *owner, *id, *days, true
}

func ingest(args []string) int {
	if len(args) == 0 || args[0] != "seo" {
		return fail(fmt.Errorf("usage: pulse ingest seo ..."))
	}
	fs := flag.NewFlagSet("ingest seo", flag.ContinueOnError)
	owner := fs.String("owner", "", "")
	id := fs.String("measurement", "", "")
	file := fs.String("file", "", "")
	expected := fs.Int("expected", 0, "")
	if fs.Parse(args[1:]) != nil {
		return 2
	}
	f, err := os.Open(*file)
	if err != nil {
		return fail(err)
	}
	defer f.Close()
	batch := model.Batch{ID: time.Now().UTC().Format("20060102T150405Z"), Source: "seo-scan", TimestampMs: time.Now().UnixMilli(), ExpectedCount: *expected}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		var row struct {
			URL, FinalURL, Cache, Error string
			Status                      int
			TTFBMs, Bytes               int64
		}
		if json.Unmarshal(scanner.Bytes(), &row) != nil {
			continue
		}
		batch.Observations = append(batch.Observations, model.Observation{URL: row.URL, FinalURL: row.FinalURL, Cache: row.Cache, Error: row.Error, Status: row.Status, TTFBMs: row.TTFBMs, Bytes: row.Bytes, TargetID: row.URL, Source: "seo-scan", TimestampMs: batch.TimestampMs})
	}
	if err := scanner.Err(); err != nil {
		return fail(err)
	}
	if batch.ExpectedCount == 0 {
		batch.ExpectedCount = len(batch.Observations)
	}
	var out any
	err = remote().DoJSON(context.Background(), "POST", fmt.Sprintf("/v1/admin/owners/%s/measurements/%s/batches", *owner, *id), os.Getenv("PULSE_ADMIN_TOKEN"), batch, &out)
	if err != nil {
		return fail(err)
	}
	printJSON(out)
	return 0
}

func readJSON(path string, dst any) error {
	if path == "" {
		return fmt.Errorf("--file is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}
func printJSON(v any) { b, _ := json.MarshalIndent(v, "", "  "); fmt.Println(string(b)) }
func fail(err error) int {
	if err == nil {
		return 0
	}
	fmt.Fprintln(os.Stderr, "pulse:", err)
	return 1
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
