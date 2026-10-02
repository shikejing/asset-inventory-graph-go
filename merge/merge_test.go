package merge

import (
	"testing"

	"github.com/shikejing/asset-inventory-graph-go/model"
)

func TestSourcePriorityWinsAndProvenance(t *testing.T) {
	m := NewMerger(Config{
		SourcePriority:  map[string]int{"cmdb": 100, "nmap": 50},
		DefaultStrategy: StrategySourcePriority,
	})
	provs := []model.Provenance{
		{Source: "nmap", Timestamp: 200, Value: "linux-nmap"},
		{Source: "cmdb", Timestamp: 1, Value: "rhel"},
	}
	attr := m.MergeScalar("os", provs)
	if attr.Value != "rhel" {
		t.Fatalf("high priority source must win, got %q", attr.Value)
	}
	if len(attr.History) != 2 || attr.History[0].Source != "cmdb" || attr.History[1].Source != "nmap" {
		t.Fatalf("history must keep all evidence in order: %+v", attr.History)
	}
}

func TestOrderIndependence(t *testing.T) {
	cfg := Config{SourcePriority: map[string]int{"a": 1, "b": 1, "c": 1}, DefaultStrategy: StrategySourcePriority}
	m := NewMerger(cfg)
	p1 := []model.Provenance{
		{Source: "c", Timestamp: 2, Value: "z"},
		{Source: "a", Timestamp: 1, Value: "m"},
		{Source: "b", Timestamp: 3, Value: "a"},
	}
	p2 := []model.Provenance{p1[2], p1[0], p1[1]}
	r1 := m.MergeScalar("os", p1)
	r2 := m.MergeScalar("os", p2)
	if r1.Value != r2.Value || r1.Value != "a" {
		// 同优先级取最新 -> b@3 -> value "a"
		t.Fatalf("result must be order independent: %q vs %q", r1.Value, r2.Value)
	}
}

func TestLatestStrategy(t *testing.T) {
	m := NewMerger(Config{
		SourcePriority: map[string]int{"low": 1, "high": 9},
		Strategies:     map[string]Strategy{"banner": StrategyLatest},
	})
	attr := m.MergeScalar("banner", []model.Provenance{
		{Source: "high", Timestamp: 10, Value: "old-but-priority"},
		{Source: "low", Timestamp: 99, Value: "newest"},
	})
	if attr.Value != "newest" {
		t.Fatalf("latest must win under latest strategy, got %q", attr.Value)
	}
}

func TestMergeSetDedupAndSources(t *testing.T) {
	m := NewMerger(DefaultConfig())
	vps := m.MergeSet("hostnames", []model.Provenance{
		{Source: "a", Timestamp: 1, Value: "h1"},
		{Source: "b", Timestamp: 2, Value: "h1"},
		{Source: "a", Timestamp: 3, Value: "h2"},
	})
	if len(vps) != 2 {
		t.Fatalf("set size: %v", vps)
	}
	if vps[0].Value != "h1" || len(vps[0].Sources) != 2 {
		t.Fatalf("h1 sources: %+v", vps[0])
	}
}

func TestIdempotentReapply(t *testing.T) {
	m := NewMerger(DefaultConfig())
	in := []model.Provenance{{Source: "x", Timestamp: 1, Value: "v"}, {Source: "x", Timestamp: 1, Value: "v"}}
	attr := m.MergeScalar("os", in)
	if len(attr.History) != 1 {
		t.Fatalf("duplicate evidence must collapse: %v", attr.History)
	}
}
