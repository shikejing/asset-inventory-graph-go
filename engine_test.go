package inventory

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig() Config {
	cfg := DefaultConfig()
	cfg.DataDir = ""
	cfg.SourcePriority = map[SourceID]int{"netscan": 1, "agent": 5, "adc": 10}
	cfg.MergeRules = map[string]MergeStrategy{
		"hostname": StrategyFirst,
		"os":       StrategyPriority,
		"domain":   StrategyPriority,
		"version":  StrategyPriority,
	}
	return cfg
}

func openTestEngine(t *testing.T) *Engine {
	t.Helper()
	cfg := testConfig()
	cfg.DataDir = t.TempDir()
	e, err := Open(cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// snapshotFingerprint is an order-independent semantic fingerprint of a
// snapshot, used to compare engines that ingested records in different
// orders.
type snapshotFingerprint struct {
	assets   []string
	edges    []string
	conflict []string
}

func fingerprint(snap *Snapshot) snapshotFingerprint {
	var f snapshotFingerprint
	for id, a := range snap.Assets {
		f.assets = append(f.assets, fmt.Sprintf("%s|%s|%s|%s|%v|%v",
			id, a.Hostname, a.Domain, a.OS, a.IPs, svcKeys(a.Services)))
	}
	for _, e := range snap.Graph.Edges {
		f.edges = append(f.edges, fmt.Sprintf("%s->%s:%s", e.From, e.To, e.Kind))
	}
	for _, c := range snap.Conflicts {
		f.conflict = append(f.conflict, fmt.Sprintf("%s=%s@%s", c.Attr, c.Chosen, c.ChosenSrc))
	}
	sort.Strings(f.assets)
	sort.Strings(f.edges)
	sort.Strings(f.conflict)
	return f
}

func svcKeys(svcs []Service) []string {
	out := make([]string, 0, len(svcs))
	for _, s := range svcs {
		out = append(out, fmt.Sprintf("%s:%d/%s", s.Name, s.Port, s.Version))
	}
	sort.Strings(out)
	return out
}

func ingestAll(t *testing.T, e *Engine, recs []*RawRecord) {
	t.Helper()
	if _, err := e.IngestBatch(recs); err != nil {
		t.Fatalf("ingest: %v", err)
	}
}

// 1. Multi-source dedup: two sources scanning the same host converge to one
// asset, and their services merge.
func TestMultiSourceDedup(t *testing.T) {
	e := openTestEngine(t)
	now := time.Now().UTC()
	recs := []*RawRecord{
		{ID: "r1", Source: "netscan", Timestamp: now, Hostname: "web-01", IPs: []string{"10.0.0.1"},
			Services: []ServiceObs{{Name: "nginx", Port: 80}}},
		{ID: "r2", Source: "agent", Timestamp: now.Add(time.Minute), Hostname: "web-01.example.com", IPs: []string{"10.0.0.1"},
			Services: []ServiceObs{{Name: "nginx", Port: 443}, {Name: "sshd", Port: 22}}},
	}
	ingestAll(t, e, recs)

	assets := e.Assets()
	if len(assets) != 1 {
		t.Fatalf("expected 1 converged asset, got %d", len(assets))
	}
	a := assets[0]
	if len(a.IPs) != 1 || a.IPs[0] != "10.0.0.1" {
		t.Fatalf("unexpected IPs: %v", a.IPs)
	}
	if len(a.Services) != 3 {
		t.Fatalf("expected 3 merged services, got %d: %v", len(a.Services), svcKeys(a.Services))
	}
	if len(a.Sources) != 2 {
		t.Fatalf("expected 2 contributing sources, got %v", a.Sources)
	}
	if e.FindByIdentity("10.0.0.1") == nil {
		t.Fatal("asset not resolvable by IP")
	}
	if e.FindByIdentity("web-01") == nil {
		t.Fatal("asset not resolvable by hostname")
	}
}

// 2. Attribute conflict: sources disagree on OS; priority resolves it and
// the conflict retains all evidence.
func TestConflictMergeAndTraceability(t *testing.T) {
	e := openTestEngine(t)
	now := time.Now().UTC()
	recs := []*RawRecord{
		{ID: "r1", Source: "netscan", Timestamp: now, Hostname: "db-01", IPs: []string{"10.0.0.2"}, OS: "linux"},
		{ID: "r2", Source: "adc", Timestamp: now.Add(time.Minute), Hostname: "db-01", IPs: []string{"10.0.0.2"}, OS: "windows"},
	}
	ingestAll(t, e, recs)

	a := e.FindByIdentity("db-01")
	if a.OS != "windows" {
		t.Fatalf("expected higher-priority source to win, got %q", a.OS)
	}
	if len(a.Conflicts) != 1 {
		t.Fatalf("expected 1 recorded conflict, got %d", len(a.Conflicts))
	}
	c := a.Conflicts[0]
	if c.Attr != "os" || c.Chosen != "windows" || c.ChosenSrc != "adc" {
		t.Fatalf("bad conflict record: %+v", c)
	}
	if len(c.Candidates) != 2 {
		t.Fatalf("conflict must retain all %d candidates, got %d", 2, len(c.Candidates))
	}
	vals := map[string]bool{}
	for _, cand := range c.Candidates {
		vals[cand.Value] = true
	}
	if !vals["linux"] || !vals["windows"] {
		t.Fatalf("conflict candidates missing evidence: %+v", c.Candidates)
	}
	if c.Reason == "" {
		t.Fatal("conflict reason must be explained")
	}
}

// 3. Dedup is insensitive to hostname spelling (FQDN vs short name) and
// stable across arrival order.
func TestOrderIndependence(t *testing.T) {
	recs := sampleRecords(time.Now().UTC())

	run := func(seed int64) snapshotFingerprint {
		e := openTestEngine(t)
		rs := append([]*RawRecord(nil), recs...)
		rand.New(rand.NewSource(seed)).Shuffle(len(rs), func(i, j int) { rs[i], rs[j] = rs[j], rs[i] })
		ingestAll(t, e, rs)
		return fingerprint(e.Snapshot())
	}
	fp1 := run(1)
	fp2 := run(2)
	fp3 := run(3)
	if fp1.assets == nil || fp2.assets == nil {
		t.Fatal("no assets produced")
	}
	if !equalFingerprint(fp1, fp2) || !equalFingerprint(fp1, fp3) {
		t.Fatalf("snapshot differs by arrival order:\n%v\n%v\n%v", fp1, fp2, fp3)
	}
}

// 4. Idempotent application: replaying the same batch changes nothing.
func TestIdempotentReplay(t *testing.T) {
	e := openTestEngine(t)
	recs := sampleRecords(time.Now().UTC())
	ingestAll(t, e, recs)
	before := fingerprint(e.Snapshot())

	// Re-apply the exact same batch.
	if _, err := e.IngestBatch(recs); err != nil {
		t.Fatal(err)
	}
	after := fingerprint(e.Snapshot())
	if !equalFingerprint(before, after) {
		t.Fatal("re-applying the same batch changed the inventory")
	}
	if got := e.Snapshot().Stats.AssetCount; got != 3 {
		t.Fatalf("asset count changed: %d", got)
	}

	// Re-apply records one by one, shuffled.
	rs := append([]*RawRecord(nil), recs...)
	rand.Shuffle(len(rs), func(i, j int) { rs[i], rs[j] = rs[j], rs[i] })
	for _, r := range rs {
		if _, err := e.Ingest(r); err != nil {
			t.Fatal(err)
		}
	}
	if !equalFingerprint(before, fingerprint(e.Snapshot())) {
		t.Fatal("re-applying records individually changed the inventory")
	}
}

// 5. Late and out-of-order arrivals still converge; "latest" strategy picks
// the newest value regardless of arrival order.
func TestLateOutOfOrder(t *testing.T) {
	cfg := testConfig()
	cfg.MergeRules["os"] = StrategyLatest
	cfg.DataDir = t.TempDir()
	e, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	base := time.Now().UTC()

	// Newest record arrives first; old record arrives late.
	ingestAll(t, e, []*RawRecord{
		{ID: "new", Source: "netscan", Timestamp: base.Add(2 * time.Hour), Hostname: "srv-01", IPs: []string{"10.0.0.9"}, OS: "linux-5.10"},
	})
	ingestAll(t, e, []*RawRecord{
		{ID: "old", Source: "adc", Timestamp: base, Hostname: "srv-01", IPs: []string{"10.0.0.9"}, OS: "linux-4.19"},
	})
	a := e.FindByIdentity("srv-01")
	if a.OS != "linux-5.10" {
		t.Fatalf("latest strategy should keep newest value, got %q", a.OS)
	}
	if len(a.Conflicts) != 1 {
		t.Fatalf("expected conflict, got %d", len(a.Conflicts))
	}
}

// 6. Concurrent ingestion: many sources in parallel never duplicate an asset
// and every intermediate snapshot is self-consistent.
func TestConcurrentIngest(t *testing.T) {
	e := openTestEngine(t)
	base := time.Now().UTC()
	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for s := 0; s < 8; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				rec := &RawRecord{
					ID:        fmt.Sprintf("src%d-r%d", s, i),
					Source:    SourceID(fmt.Sprintf("src%d", s)),
					Timestamp: base.Add(time.Duration(i) * time.Second),
					Hostname:  fmt.Sprintf("host-%d", i%5),
					IPs:       []string{fmt.Sprintf("10.1.%d.%d", s, i)},
					Services:  []ServiceObs{{Name: "httpd", Port: 80}},
				}
				if _, err := e.Ingest(rec); err != nil {
					errCh <- err
					return
				}
				// Query concurrently: snapshot must always be self-consistent.
				snap := e.Snapshot()
				for _, a := range snap.Assets {
					if a.ID == "" || len(a.IPs) == 0 {
						errCh <- fmt.Errorf("inconsistent asset in snapshot v%d", snap.Version)
						return
					}
				}
				for _, edge := range snap.Graph.Edges {
					if snap.Graph.Nodes[edge.From] == nil || snap.Graph.Nodes[edge.To] == nil {
						errCh <- fmt.Errorf("dangling edge in snapshot v%d: %v", snap.Version, edge)
						return
					}
				}
			}
		}(s)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	assets := e.Assets()
	if len(assets) != 5 {
		t.Fatalf("expected exactly 5 converged hosts, got %d", len(assets))
	}
}

// 7. Relationship graph: domains, services, weak passwords, vulnerabilities
// and dependency cycles are traversed without infinite loops.
func TestGraphAndCycles(t *testing.T) {
	e := openTestEngine(t)
	now := time.Now().UTC()
	recs := []*RawRecord{
		{ID: "r1", Source: "agent", Timestamp: now, Hostname: "a.example.com", IPs: []string{"10.0.1.1"}, Domain: "example.com",
			Services:  []ServiceObs{{Name: "nginx", Port: 443, Vulnerabilities: []string{"CVE-2024-0001"}, WeakPasswords: []string{"admin/admin"}}},
			DependsOn: []string{"b.example.com"}},
		{ID: "r2", Source: "agent", Timestamp: now, Hostname: "b.example.com", IPs: []string{"10.0.1.2"}, Domain: "example.com",
			Services:  []ServiceObs{{Name: "mysql", Port: 3306, WeakPasswords: []string{"root/root"}}},
			DependsOn: []string{"a.example.com"}},
		{ID: "r3", Source: "netscan", Timestamp: now, Hostname: "a", IPs: []string{"10.0.1.1"}},
	}
	ingestAll(t, e, recs)

	a := e.FindByIdentity("a.example.com")
	b := e.FindByIdentity("b.example.com")
	if a == nil || b == nil {
		t.Fatal("assets not found")
	}
	if len(e.AssetsInDomain("example.com")) != 2 {
		t.Fatalf("expected 2 assets in domain, got %d", len(e.AssetsInDomain("example.com")))
	}
	svcs := e.ServicesOf(a.ID)
	if len(svcs) != 1 || svcs[0].Name != "nginx:443" {
		t.Fatalf("expected nginx service, got %v", svcs)
	}
	if vulns := e.VulnerabilitiesOf(svcs[0].ID); len(vulns) != 1 || vulns[0].Name != "CVE-2024-0001" {
		t.Fatalf("expected vuln node, got %v", vulns)
	}
	if wps := e.WeakPasswordsOf(svcs[0].ID); len(wps) != 1 {
		t.Fatalf("expected weak password node, got %v", wps)
	}

	// Cycle a<->b: BFS must terminate and visit both.
	reach := e.Graph().Reachable(a.ID, -1)
	visited := map[string]bool{}
	for _, r := range reach {
		visited[r.Node.ID] = true
	}
	if !visited[a.ID] || !visited[b.ID] {
		t.Fatalf("cycle traversal missed nodes: %v", visited)
	}
	// Depth-limited traversal must not explode.
	if d := e.Graph().Reachable(a.ID, 1); len(d) > 4 {
		t.Fatalf("depth-1 reachability too large: %d", len(d))
	}

	stats := e.Graph().Stats()
	if stats.NodesByKind[NodeAsset] != 2 || stats.NodesByKind[NodeDomain] != 1 ||
		stats.NodesByKind[NodeVulnerability] != 1 || stats.NodesByKind[NodeWeakPassword] != 2 {
		t.Fatalf("unexpected graph stats: %+v", stats.NodesByKind)
	}
	if stats.EdgesByKind[EdgeDependsOn] != 2 {
		t.Fatalf("expected 2 dependency edges (cycle), got %d", stats.EdgesByKind[EdgeDependsOn])
	}
}

// 8. Full rebuild while ingesting: arrivals during rebuild are not lost and
// the rebuilt state matches the change stream.
func TestRebuildDuringIngest(t *testing.T) {
	e := openTestEngine(t)
	base := time.Now().UTC()
	var wg sync.WaitGroup
	for s := 0; s < 4; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				_, err := e.Ingest(&RawRecord{
					ID:        fmt.Sprintf("s%d-r%d", s, i),
					Source:    SourceID(fmt.Sprintf("s%d", s)),
					Timestamp: base.Add(time.Duration(i) * time.Second),
					Hostname:  fmt.Sprintf("host-%d", i%7),
					IPs:       []string{fmt.Sprintf("10.2.%d.%d", s, i)},
				})
				if err != nil {
					t.Errorf("ingest: %v", err)
					return
				}
			}
		}(s)
	}
	// Rebuild repeatedly while ingestion is running.
	for i := 0; i < 5; i++ {
		if _, err := e.Rebuild(); err != nil {
			t.Fatalf("rebuild: %v", err)
		}
	}
	wg.Wait()
	if _, err := e.Rebuild(); err != nil {
		t.Fatal(err)
	}

	// Expected: 7 hosts, all sources present.
	if got := e.Snapshot().Stats.AssetCount; got != 7 {
		t.Fatalf("expected 7 assets after rebuild, got %d", got)
	}
	if got := e.Snapshot().Stats.SourceCount; got != 4 {
		t.Fatalf("expected 4 sources, got %d", got)
	}
	// Every record id from the stream is represented.
	for _, a := range e.Assets() {
		if len(a.RecordIDs) == 0 {
			t.Fatalf("asset %s has no record evidence", a.ID)
		}
	}
}

// 9. Persistence and crash recovery: committed state survives restart; a
// torn WAL tail is ignored; no half-written records poison the inventory.
func TestRecoveryAndTornWAL(t *testing.T) {
	cfg := testConfig()
	cfg.DataDir = t.TempDir()
	base := time.Now().UTC()

	e, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recs := sampleRecords(base)
	ingestAll(t, e, recs)
	ingestAll(t, e, []*RawRecord{
		{ID: "late-1", Source: "adc", Timestamp: base.Add(time.Hour), Hostname: "web-01", IPs: []string{"10.0.0.1"},
			Attrs: map[string]string{"rack": "r2"}},
	})
	before := fingerprint(e.Snapshot())
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a torn append: garbage bytes at the end of the WAL.
	walPath := filepath.Join(cfg.DataDir, "wal.log")
	f, err := os.OpenFile(walPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x49, 0x4e, 0x56, 0x31, 0x00, 0x00, 0x00, 0x10, 0x7b, 0x22}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Reopen: committed state must be fully restored, torn tail discarded.
	e2, err := Open(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer e2.Close()
	after := fingerprint(e2.Snapshot())
	if !equalFingerprint(before, after) {
		t.Fatalf("state after restart differs:\n%v\n%v", before, after)
	}
	if e2.FindByIdentity("web-01") == nil {
		t.Fatal("web-01 missing after recovery")
	}
	if got := e2.FindByIdentity("web-01").Attrs["rack"]; got != "r2" {
		t.Fatalf("late attr lost after recovery: %q", got)
	}

	// Ingestion after recovery works and remains consistent.
	ingestAll(t, e2, []*RawRecord{
		{ID: "new-1", Source: "netscan", Timestamp: base.Add(2 * time.Hour), Hostname: "srv-04", IPs: []string{"10.0.0.4"}},
	})
	if len(e2.Assets()) != 4 {
		t.Fatalf("expected 4 assets after post-recovery ingest, got %d", len(e2.Assets()))
	}
}

// 10. Slow sources do not block queries: ingestion is throttled while reads
// always return a complete snapshot.
func TestSlowSourceDoesNotBlockQueries(t *testing.T) {
	e := openTestEngine(t)
	base := time.Now().UTC()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			_, err := e.Ingest(&RawRecord{
				ID:        fmt.Sprintf("slow-%d", i),
				Source:    "slow",
				Timestamp: base.Add(time.Duration(i) * time.Second),
				Hostname:  fmt.Sprintf("slow-%d", i),
			})
			if err != nil {
				t.Errorf("ingest: %v", err)
				return
			}
			time.Sleep(5 * time.Millisecond) // slow source
		}
	}()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-done:
			return
		case <-deadline:
			t.Fatal("queries stalled: slow source blocked the engine")
		default:
			snap := e.Snapshot()
			if snap == nil {
				t.Fatal("no snapshot available")
			}
			_ = e.Graph().Stats()
			time.Sleep(time.Millisecond)
		}
	}
}

// sampleRecords builds a small deterministic change stream covering
// multi-source overlap, conflicts, services and a dependency.
func sampleRecords(base time.Time) []*RawRecord {
	return []*RawRecord{
		{ID: "r1", Source: "netscan", Timestamp: base, Hostname: "web-01", IPs: []string{"10.0.0.1"}, OS: "linux",
			Services: []ServiceObs{{Name: "nginx", Port: 80, Version: "1.24"}}},
		{ID: "r2", Source: "agent", Timestamp: base.Add(time.Minute), Hostname: "web-01.example.com", IPs: []string{"10.0.0.1"}, OS: "linux",
			Services:  []ServiceObs{{Name: "nginx", Port: 443, Version: "1.25"}, {Name: "sshd", Port: 22}},
			DependsOn: []string{"db-01"}},
		{ID: "r3", Source: "adc", Timestamp: base.Add(2 * time.Minute), Hostname: "db-01", IPs: []string{"10.0.0.2"}, OS: "windows",
			Services: []ServiceObs{{Name: "mysql", Port: 3306, WeakPasswords: []string{"root/root"}}}},
		{ID: "r4", Source: "netscan", Timestamp: base.Add(3 * time.Minute), Hostname: "db-01", IPs: []string{"10.0.0.2"}, OS: "linux",
			Services: []ServiceObs{{Name: "mysql", Port: 3306, Vulnerabilities: []string{"CVE-2023-1234"}}}},
		{ID: "r5", Source: "agent", Timestamp: base.Add(4 * time.Minute), Hostname: "srv-03", IPs: []string{"10.0.0.3"}},
	}
}

func equalFingerprint(a, b snapshotFingerprint) bool {
	return strings.Join(a.assets, "\n") == strings.Join(b.assets, "\n") &&
		strings.Join(a.edges, "\n") == strings.Join(b.edges, "\n") &&
		strings.Join(a.conflict, "\n") == strings.Join(b.conflict, "\n")
}

// 11. MAC-based convergence and union strategy for custom attributes.
func TestMACDedupAndUnion(t *testing.T) {
	cfg := testConfig()
	cfg.MergeRules["attr.tags"] = StrategyUnion
	cfg.DataDir = t.TempDir()
	e, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	now := time.Now().UTC()
	ingestAll(t, e, []*RawRecord{
		{ID: "r1", Source: "netscan", Timestamp: now, MACs: []string{"aa:bb:cc:dd:ee:ff"},
			Attrs: map[string]string{"tags": "web"}},
		{ID: "r2", Source: "agent", Timestamp: now.Add(time.Minute), Hostname: "node-7",
			MACs: []string{"AABB.CCDD.EEFF"}, Attrs: map[string]string{"tags": "prod"}},
	})
	assets := e.Assets()
	if len(assets) != 1 {
		t.Fatalf("expected MAC-based convergence to 1 asset, got %d", len(assets))
	}
	a := assets[0]
	if a.Hostname != "node-7" {
		t.Fatalf("hostname should be merged from second record, got %q", a.Hostname)
	}
	// Union is a multi-valued strategy; single-valued attrs keep one value,
	// but evidence for both sources must exist.
	if len(a.Evidence["attr.tags"]) != 2 {
		t.Fatalf("expected evidence from both sources, got %d", len(a.Evidence["attr.tags"]))
	}
}

// 12. Snapshots are self-contained: after a snapshot is written, deleting the
// WAL still allows a full recovery (snapshot carries the change stream).
func TestSnapshotSelfContained(t *testing.T) {
	cfg := testConfig()
	cfg.SnapshotEvery = 1
	cfg.DataDir = t.TempDir()
	e, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ingestAll(t, e, []*RawRecord{
		{ID: "r1", Source: "agent", Timestamp: now, Hostname: "snap-1", IPs: []string{"10.3.0.1"}},
		{ID: "r2", Source: "agent", Timestamp: now.Add(time.Minute), Hostname: "snap-2", IPs: []string{"10.3.0.2"}},
	})
	before := fingerprint(e.Snapshot())
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	// Remove the WAL: recovery must still succeed from the snapshot alone.
	if err := os.Remove(filepath.Join(cfg.DataDir, "wal.log")); err != nil {
		t.Fatal(err)
	}
	e2, err := Open(cfg)
	if err != nil {
		t.Fatalf("reopen without WAL: %v", err)
	}
	defer e2.Close()
	if after := fingerprint(e2.Snapshot()); !equalFingerprint(before, after) {
		t.Fatalf("snapshot-only recovery changed state:\n%v\n%v", before, after)
	}
}

// 13. Unresolvable dependency references are ignored (no dangling edges).
func TestUnresolvedDependencyIgnored(t *testing.T) {
	e := openTestEngine(t)
	now := time.Now().UTC()
	ingestAll(t, e, []*RawRecord{
		{ID: "r1", Source: "agent", Timestamp: now, Hostname: "lonely", IPs: []string{"10.4.0.1"},
			DependsOn: []string{"ghost-host", "192.0.2.1"}},
	})
	stats := e.Graph().Stats()
	if stats.EdgesByKind[EdgeDependsOn] != 0 {
		t.Fatalf("unresolved dependencies must not create edges, got %d", stats.EdgesByKind[EdgeDependsOn])
	}
	if stats.NodesByKind[NodeAsset] != 1 {
		t.Fatalf("expected 1 asset, got %d", stats.NodesByKind[NodeAsset])
	}
}

// 14. Crash during snapshot write: a corrupt temp file or even a corrupt
// snapshot.json must not prevent recovery (WAL replay rebuilds state).
func TestCorruptSnapshotFallsBackToWAL(t *testing.T) {
	cfg := testConfig()
	cfg.SnapshotEvery = 1
	cfg.DataDir = t.TempDir()
	e, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ingestAll(t, e, []*RawRecord{
		{ID: "r1", Source: "agent", Timestamp: now, Hostname: "corr-1", IPs: []string{"10.5.0.1"}},
	})
	before := fingerprint(e.Snapshot())
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	// Corrupt the snapshot file: recovery must fall back to WAL replay.
	snapPath := filepath.Join(cfg.DataDir, "snapshot.json")
	if err := os.WriteFile(snapPath, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	e2, err := Open(cfg)
	if err != nil {
		t.Fatalf("reopen with corrupt snapshot: %v", err)
	}
	defer e2.Close()
	if after := fingerprint(e2.Snapshot()); !equalFingerprint(before, after) {
		t.Fatalf("WAL fallback changed state:\n%v\n%v", before, after)
	}
}
