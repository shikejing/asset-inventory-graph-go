package engine_test

import (
	"testing"

	"github.com/shikejing/asset-inventory-graph-go/model"
)

// 3) 关系图构建/查询与环安全统计。
func TestRelationsAndQueries(t *testing.T) {
	eng := newEngine(t)
	_ = eng.Ingest(model.RawRecord{
		Source: "nmap", Timestamp: 1, Hostnames: []string{"web"}, IPNets: []string{"10.0.0.5", "10.0.0.0/24"},
		Domain: "example.com",
		Services: []model.RawService{
			{Port: 22, Protocol: "tcp", Name: "ssh",
				Creds: []model.RawCredential{{Username: "root", AuthType: "password", Detail: "123456"}}},
			{Port: 80, Protocol: "tcp", Name: "http",
				Vulns: []model.RawVuln{{ID: "CVE-1", Title: "RCE", Severity: "critical"}}},
		},
	})
	snap := eng.Snapshot()
	a, ok := snap.FindByIP("10.0.0.5")
	if !ok {
		t.Fatal("find by ip")
	}
	if a2, ok := snap.FindByIP("10.0.0.99"); !ok || a2.ID != a.ID {
		// 10.0.0.99 落在 10.0.0.0/24 网段属性内
		t.Fatal("find by ip within CIDR failed")
	}
	if ids := snap.DomainAssets("example.com"); len(ids) != 1 || ids[0] != a.ID {
		t.Fatalf("domain assets: %v", ids)
	}
	rel := snap.AssetRelations(a.ID)
	want := map[string]bool{
		"svc:" + a.ID + ":tcp/22": true,
		"svc:" + a.ID + ":tcp/80": true,
		"vuln:CVE-1":              true,
		"dom:example.com":         true,
	}
	for _, r := range rel {
		delete(want, r)
	}
	if len(want) != 0 {
		t.Fatalf("missing relations: %v (got %v)", want, rel)
	}
	st := snap.Stats()
	if st.AssetCount != 1 || st.ServiceCount != 2 || st.VulnCount != 1 ||
		st.CredCount != 1 || st.DomainCount != 1 || st.EdgeCount < 5 {
		t.Fatalf("stats: %+v", st)
	}
}

// 慢来源不阻塞查询：快照始终可读且是已提交版本。
func TestSlowSourceDoesNotBlockQueries(t *testing.T) {
	eng := newEngine(t)
	_ = eng.Ingest(rec("a", 1, []string{"h"}, []string{"1.1.1.1"}, "os1", ""))
	v1 := eng.Version()
	done := make(chan struct{})
	go func() {
		defer close(done)
		// 模拟一个耗时提交（真实场景为 fsync 慢），期间查询必须照常推进。
		_ = eng.Ingest(rec("b", 2, []string{"h"}, []string{"1.1.1.1"}, "os2", ""))
	}()
	_ = eng.Snapshot() // 无锁读取，立即返回
	<-done
	if eng.Version() <= v1 {
		t.Fatal("version should advance after ingest")
	}
}
