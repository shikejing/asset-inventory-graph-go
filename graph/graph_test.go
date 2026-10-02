package graph

import (
	"strconv"
	"testing"
	"time"

	"github.com/shikejing/asset-inventory-graph-go/model"
)

func asset(id, domain string, ports []int, vuln, cred string) *model.Asset {
	a := &model.Asset{
		ID: id, PrimaryID: id,
		Domain:   model.Attribute{Value: domain},
		Services: map[string]*model.Service{},
		Vulns:    map[string]*model.Vuln{},
		Creds:    map[string]*model.WeakCred{},
	}
	for _, p := range ports {
		key := "tcp/" + strconv.Itoa(p)
		svc := &model.Service{Port: p, Protocol: "tcp", Key: key}
		if vuln != "" && p == ports[0] {
			svc.VulnIDs = []string{vuln}
		}
		if cred != "" && p == ports[0] {
			svc.CredIDs = []string{cred}
		}
		a.Services[key] = svc
	}
	if vuln != "" {
		a.Vulns[vuln] = &model.Vuln{ID: vuln}
	}
	return a
}

func TestBuildAndRelations(t *testing.T) {
	a1 := asset("asset1", "example.com", []int{22, 80}, "vuln:CVE-1", "cred:22/abc")
	g := NewBuilder().Build(map[string]*model.Asset{"asset1": a1})
	if len(g.Edges) != 6 { // domain 1 + services 2 + asset->vuln 1 + service->vuln 1 + cred 1
		t.Fatalf("edges: %d %v", len(g.Edges), g.Edges)
	}
	got := g.ReachableFrom("asset:asset1")
	want := map[string]bool{
		"dom:example.com":   true,
		"svc:asset1:tcp/22": true,
		"svc:asset1:tcp/80": true,
		"vuln:CVE-1":        true,
		"cred:22/abc":       true,
	}
	if len(got) != len(want) {
		t.Fatalf("reachable %v", got)
	}
	for _, n := range got {
		if !want[n] {
			t.Fatalf("unexpected %s", n)
		}
	}
	if rev := g.ReverseNeighbors("dom:example.com"); len(rev) != 1 || rev[0] != "asset:asset1" {
		t.Fatalf("reverse: %v", rev)
	}
}

func TestCycleSafe(t *testing.T) {
	a1 := asset("asset1", "", []int{22}, "", "")
	g := NewBuilder().Build(map[string]*model.Asset{"asset1": a1})
	// 人为制造环：service -> domain -> asset（正常数据不会出现，验证遍历健壮性）
	g.Kind["dom:loop"] = NodeDomain
	g.addEdge(model.Edge{From: "svc:asset1:tcp/22", To: "dom:loop", Kind: model.EdgeAssetDomain})
	g.addEdge(model.Edge{From: "dom:loop", To: "asset:asset1", Kind: model.EdgeAssetDomain})

	done := make(chan struct{})
	go func() {
		_ = g.ReachableFrom("asset:asset1")
		_ = g.CycleCount()
		_ = g.DetectCycle()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("traversal must terminate on cyclic graph")
	}
	cyc := g.DetectCycle()
	if len(cyc) < 3 || cyc[0] != cyc[len(cyc)-1] {
		t.Fatalf("cycle path: %v", cyc)
	}
	if g.CycleCount() == 0 {
		t.Fatal("cycle count must detect the back edge")
	}
}

func TestStats(t *testing.T) {
	a1 := asset("a", "d", []int{22}, "vuln:v", "")
	a2 := asset("b", "d", []int{443}, "", "")
	g := NewBuilder().Build(map[string]*model.Asset{"a": a1, "b": a2})
	cnt := g.CountByKind()
	if cnt[NodeAsset] != 2 || cnt[NodeService] != 2 || cnt[NodeDomain] != 1 || cnt[NodeVuln] != 1 {
		t.Fatalf("counts: %v", cnt)
	}
}
