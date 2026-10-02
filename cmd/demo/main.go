// Command demo runs a fully self-contained simulation of the asset
// inventory engine: multiple scanning sources feed raw records through
// in-memory pipes (channels) into the engine. No external service is used.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	inventory "github.com/shikejing/asset-inventory-graph-go"
)

func main() {
	dir, err := os.MkdirTemp("", "inventory-demo-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	cfg := inventory.DefaultConfig()
	cfg.DataDir = dir
	cfg.SourcePriority = map[inventory.SourceID]int{
		"netscan": 1,  // network scanner: lowest priority for host attributes
		"agent":   5,  // on-host agent
		"adc":     10, // authoritative asset database: highest priority
	}
	cfg.MergeRules["os"] = inventory.StrategyPriority
	cfg.MergeRules["hostname"] = inventory.StrategyFirst

	eng, err := inventory.Open(cfg)
	if err != nil {
		panic(err)
	}

	// In-memory pipes: each source goroutine writes raw records to a channel;
	// a single ingester drains the channel into the engine. Sources never
	// touch the engine directly.
	records := make(chan *inventory.RawRecord, 64)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go netscanSource(ctx, records)
	go agentSource(ctx, records)
	go adcSource(ctx, records)

	ingested := make(chan struct{})
	go func() {
		for r := range records {
			if _, err := eng.Ingest(r); err != nil {
				fmt.Fprintf(os.Stderr, "ingest: %v\n", err)
			}
			// Simulate a slow source occasionally: queries must still proceed.
			if r.Source == "netscan" && r.ID == "ns-3" {
				time.Sleep(200 * time.Millisecond)
			}
		}
		close(ingested)
	}()

	// Let the stream flow, then exercise a full rebuild mid-stream.
	time.Sleep(150 * time.Millisecond)
	snap, err := eng.Rebuild()
	if err != nil {
		panic(err)
	}
	fmt.Printf("[mid-stream rebuild] version=%d assets=%d edges=%d conflicts=%d\n",
		snap.Version, snap.Stats.AssetCount, snap.Stats.EdgeCount, snap.Stats.ConflictCount)

	// Drain: wait for sources to finish.
	time.Sleep(600 * time.Millisecond)
	cancel()
	// Close the channel after sources have stopped writing.
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(records)
	}()
	<-ingested

	// Final rebuild to align the snapshot with the full change stream.
	snap, err = eng.Rebuild()
	if err != nil {
		panic(err)
	}

	fmt.Println("\n=== Converged asset inventory ===")
	for _, a := range eng.Assets() {
		fmt.Printf("asset %s\n", a.ID)
		fmt.Printf("  hostname : %s\n", a.Hostname)
		fmt.Printf("  ips      : %v\n", a.IPs)
		fmt.Printf("  domain   : %s\n", a.Domain)
		fmt.Printf("  os       : %s\n", a.OS)
		fmt.Printf("  ports    : %v\n", a.Ports)
		for _, s := range a.Services {
			fmt.Printf("  service  : %s:%d %s weak=%v vulns=%v\n",
				s.Name, s.Port, s.Version, s.WeakPasswords, s.Vulnerabilities)
		}
		fmt.Printf("  sources  : %v\n", a.Sources)
	}

	fmt.Println("\n=== Attribute conflicts (traceable) ===")
	for _, c := range eng.Conflicts() {
		fmt.Printf("attr %q: winner=%q (source=%s) reason=%s\n", c.Attr, c.Chosen, c.ChosenSrc, c.Reason)
		for _, cand := range c.Candidates {
			fmt.Printf("    evidence: %q from %s at %s\n", cand.Value, cand.Source, cand.Timestamp.Format(time.RFC3339))
		}
	}

	fmt.Println("\n=== Relationship graph ===")
	stats := eng.Graph().Stats()
	fmt.Printf("nodes=%d edges=%d by-kind=%v\n", stats.Nodes, stats.Edges, stats.NodesByKind)
	for _, a := range eng.Assets() {
		reach := eng.Graph().Reachable(a.ID, -1)
		fmt.Printf("from %s reachable nodes: %d\n", a.Hostname, len(reach))
	}

	// Persistence: close and reopen, state must be fully restored.
	if err := eng.Close(); err != nil {
		panic(err)
	}
	eng2, err := inventory.Open(cfg)
	if err != nil {
		panic(err)
	}
	defer eng2.Close()
	fmt.Println("\n=== After restart (recovery) ===")
	fmt.Printf("assets=%d conflicts=%d data-dir=%s\n",
		len(eng2.Assets()), len(eng2.Conflicts()), filepath.Join(dir, "snapshot.json"))
}

// netscanSource emits network-scanner observations (lowest priority).
func netscanSource(ctx context.Context, out chan<- *inventory.RawRecord) {
	base := time.Now().UTC()
	recs := []*inventory.RawRecord{
		{ID: "ns-1", Source: "netscan", Timestamp: base, Hostname: "web-01", IPs: []string{"10.0.0.1"}, OS: "linux",
			Services: []inventory.ServiceObs{{Name: "nginx", Port: 80, Version: "1.24"}}},
		{ID: "ns-2", Source: "netscan", Timestamp: base.Add(time.Second), Hostname: "db-01", IPs: []string{"10.0.0.2"}, OS: "linux",
			Services: []inventory.ServiceObs{{Name: "mysql", Port: 3306, Vulnerabilities: []string{"CVE-2023-1234"}}}},
		{ID: "ns-3", Source: "netscan", Timestamp: base.Add(2 * time.Second), Hostname: "cache-01", IPs: []string{"10.0.0.3"},
			Services: []inventory.ServiceObs{{Name: "redis", Port: 6379, WeakPasswords: []string{"redis/redis"}}}},
	}
	for _, r := range recs {
		select {
		case out <- r:
		case <-ctx.Done():
			return
		}
	}
}

// agentSource emits on-host agent observations (medium priority).
func agentSource(ctx context.Context, out chan<- *inventory.RawRecord) {
	base := time.Now().UTC()
	recs := []*inventory.RawRecord{
		{ID: "ag-1", Source: "agent", Timestamp: base.Add(30 * time.Second), Hostname: "web-01.example.com", IPs: []string{"10.0.0.1"},
			Domain: "example.com", OS: "linux",
			Services:  []inventory.ServiceObs{{Name: "nginx", Port: 443, Version: "1.25"}, {Name: "sshd", Port: 22}},
			DependsOn: []string{"db-01"}},
		{ID: "ag-2", Source: "agent", Timestamp: base.Add(31 * time.Second), Hostname: "db-01.example.com", IPs: []string{"10.0.0.2"},
			Domain: "example.com", OS: "linux",
			Services: []inventory.ServiceObs{{Name: "mysql", Port: 3306, Version: "8.0.32"}}},
	}
	for _, r := range recs {
		select {
		case out <- r:
		case <-ctx.Done():
			return
		}
	}
}

// adcSource emits authoritative asset-database observations (highest priority).
func adcSource(ctx context.Context, out chan<- *inventory.RawRecord) {
	base := time.Now().UTC()
	recs := []*inventory.RawRecord{
		{ID: "adc-1", Source: "adc", Timestamp: base.Add(time.Minute), Hostname: "web-01.example.com", IPs: []string{"10.0.0.1"},
			Domain: "corp.example.com", OS: "linux", Attrs: map[string]string{"owner": "team-web", "rack": "r1"}},
		{ID: "adc-2", Source: "adc", Timestamp: base.Add(time.Minute), Hostname: "db-01.example.com", IPs: []string{"10.0.0.2"},
			Domain: "corp.example.com", OS: "windows", Attrs: map[string]string{"owner": "team-db", "rack": "r2"}},
	}
	for _, r := range recs {
		select {
		case out <- r:
		case <-ctx.Done():
			return
		}
	}
}
