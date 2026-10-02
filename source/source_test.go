package source_test

import (
	"context"
	"testing"
	"time"

	"github.com/shikejing/asset-inventory-graph-go/engine"
	"github.com/shikejing/asset-inventory-graph-go/merge"
	"github.com/shikejing/asset-inventory-graph-go/model"
	"github.com/shikejing/asset-inventory-graph-go/source"
	"github.com/shikejing/asset-inventory-graph-go/store"
)

type idleLB struct{ *source.LoopbackServer }

func (i idleLB) Records(ctx context.Context) <-chan model.RawRecord {
	return i.LoopbackServer.Records(ctx, 300*time.Millisecond)
}

func TestRunnerFanInAndDedup(t *testing.T) {
	eng, err := engine.New(engine.Options{MergeConfig: merge.DefaultConfig(), Store: store.NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	s1 := source.NewSimSource("nmap", []model.RawRecord{
		{Source: "nmap", Timestamp: 1, Hostnames: []string{"h"}, IPNets: []string{"1.1.1.1"}, OS: "L"},
		{Source: "nmap", Timestamp: 2, Hostnames: []string{"h"}, IPNets: []string{"1.1.1.1"}, OS: "L"},
	})
	s2 := source.NewSimSource("cmdb", []model.RawRecord{
		{Source: "cmdb", Timestamp: 3, Hostnames: []string{"h"}, IPNets: []string{"1.1.1.1"}, OS: "R"},
	}).WithDelay(100 * time.Millisecond) // 慢来源

	start := time.Now()
	if err := source.NewRunner(eng).Run(context.Background(), []source.Source{s1, s2}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("slow source blocked runner")
	}
	snap := eng.Snapshot()
	if len(snap.ListAssets()) != 1 {
		t.Fatalf("assets: %d", len(snap.ListAssets()))
	}
	a := snap.ListAssets()[0]
	if a.OS.Value != "R" {
		t.Fatalf("cmdb must win: %s", a.OS.Value)
	}
}

func TestLoopbackEndToEnd(t *testing.T) {
	eng, err := engine.New(engine.Options{MergeConfig: merge.DefaultConfig(), Store: store.NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	srv, err := source.NewLoopbackServer(0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- source.NewRunner(eng).Run(context.Background(), []source.Source{idleLB{srv}})
	}()
	time.Sleep(100 * time.Millisecond)
	if err := source.SendLoopback(srv.Addr(), []model.RawRecord{
		{Source: "remote-scanner", Timestamp: 5, Hostnames: []string{"lb.example.com"}, IPNets: []string{"172.16.0.1"}},
		{Source: "remote-scanner", Timestamp: 6, Hostnames: []string{"lb.example.com"}, IPNets: []string{"172.16.0.1"},
			Services: []model.RawService{{Port: 443, Protocol: "tcp", Name: "https",
				Vulns: []model.RawVuln{{ID: "CVE-9", Title: "x", Severity: "low"}}}}},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("loopback run did not finish")
	}
	_ = srv.Close()

	a, ok := eng.Snapshot().FindByHostname("LB.Example.COM") // 大小写/尾点不敏感
	if !ok {
		t.Fatal("asset from loopback not found")
	}
	if _, ok := a.Services["tcp/443"]; !ok {
		t.Fatalf("service missing: %+v", a.Services)
	}
	if len(eng.Snapshot().AssetRelations(a.ID)) == 0 {
		t.Fatal("relations missing")
	}
}

func TestContextCancel(t *testing.T) {
	eng, _ := engine.New(engine.Options{Store: store.NewMemoryStore()})
	defer eng.Close()
	src := source.NewSimSource("slow", []model.RawRecord{
		{Source: "slow", IPNets: []string{"1.1.1.1"}},
	}).WithDelay(10 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_ = source.NewRunner(eng).Run(ctx, []source.Source{src})
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancel did not stop runner")
	}
}
