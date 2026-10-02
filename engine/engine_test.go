package engine_test

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/shikejing/asset-inventory-graph-go/engine"
	"github.com/shikejing/asset-inventory-graph-go/merge"
	"github.com/shikejing/asset-inventory-graph-go/model"
	"github.com/shikejing/asset-inventory-graph-go/store"
)

func rec(source string, ts int64, hosts, ips []string, osName, domain string) model.RawRecord {
	return model.RawRecord{Source: source, Timestamp: ts, Hostnames: hosts, IPNets: ips, OS: osName, Domain: domain}
}

func newEngine(t *testing.T) *engine.Engine {
	t.Helper()
	eng, err := engine.New(engine.Options{MergeConfig: merge.DefaultConfig(), Store: store.NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	return eng
}

func assetIDs(s *engine.Snapshot) []string {
	var out []string
	for _, a := range s.ListAssets() {
		out = append(out, a.ID)
	}
	sort.Strings(out)
	return out
}

// 1) 多来源去重：主机名/IP 互相指向的记录必须收敛成唯一资产，且与到达顺序无关。
func TestMultiSourceDedupOrderIndependent(t *testing.T) {
	build := func(order []int) []string {
		eng := newEngine(t)
		records := []model.RawRecord{
			rec("nmap", 100, []string{"web-01.example.com"}, []string{"10.0.0.5"}, "Linux", ""),
			rec("agent", 90, []string{"web-01.example.com", "web.example.com"}, []string{"10.0.0.5"}, "CentOS", "example.com"),
			rec("passive", 110, nil, []string{"10.0.0.5"}, "", ""),
		}
		for _, i := range order {
			if err := eng.Ingest(records[i]); err != nil {
				t.Fatal(err)
			}
		}
		return assetIDs(eng.Snapshot())
	}
	a := build([]int{0, 1, 2})
	b := build([]int{2, 0, 1})
	c := build([]int{1, 2, 0})
	if len(a) != 1 {
		t.Fatalf("expect single converged asset, got %v", a)
	}
	if fmt.Sprint(a) != fmt.Sprint(b) || fmt.Sprint(a) != fmt.Sprint(c) {
		t.Fatalf("dedup result must be order independent: %v %v %v", a, b, c)
	}
}

// 1b) 别名传递：A 观察连接 h1<->ip1，B 观察连接 ip1<->h2，三者必须是同一资产。
func TestTransitiveAliasMerge(t *testing.T) {
	eng := newEngine(t)
	_ = eng.Ingest(rec("a", 1, []string{"h1"}, []string{"10.0.0.9"}, "", ""))
	_ = eng.Ingest(rec("b", 2, nil, []string{"10.0.0.9", "10.0.0.10"}, "", ""))
	_ = eng.Ingest(rec("c", 3, []string{"h2"}, []string{"10.0.0.10"}, "", ""))
	if ids := assetIDs(eng.Snapshot()); len(ids) != 1 {
		t.Fatalf("transitive aliases must merge: %v", ids)
	}
}

// 2) 属性冲突：高优先级来源胜出，被覆盖依据完整保留可追溯。
func TestConflictResolutionAndTrace(t *testing.T) {
	eng := newEngine(t)
	_ = eng.Ingest(rec("nmap", 100, []string{"h"}, []string{"1.1.1.1"}, "linux-nmap", "x.com"))
	_ = eng.Ingest(rec("agent", 90, []string{"h"}, []string{"1.1.1.1"}, "centos", "x.com"))
	_ = eng.Ingest(rec("cmdb", 120, []string{"h"}, []string{"1.1.1.1"}, "rhel7", "root.example.com"))
	a := eng.Snapshot().ListAssets()[0]
	if a.OS.Value != "rhel7" || a.OS.Winner.Source != "cmdb" {
		t.Fatalf("OS winner: %+v", a.OS)
	}
	if len(a.OS.History) != 3 {
		t.Fatalf("all overwritten evidence must be retained: %+v", a.OS.History)
	}
	if a.Domain.Value != "root.example.com" {
		t.Fatalf("domain: %s", a.Domain.Value)
	}
	// 多值属性集合合并：主机名保留所有来源值
	if len(a.Hostnames) != 1 {
		t.Fatalf("hostnames: %v", a.Hostnames)
	}
}

// 4) 乱序、重复、迟到到达：增量结果 == 全量一次性结果；重复应用结论不变。
func TestIdempotentOutOfOrderLate(t *testing.T) {
	full := []model.RawRecord{
		rec("nmap", 100, []string{"h"}, []string{"1.1.1.1"}, "L", "d.com"),
		rec("agent", 90, []string{"h"}, []string{"1.1.1.1"}, "C", "d.com"),
		rec("cmdb", 120, []string{"h", "alias"}, []string{"1.1.1.1"}, "R", "d.com"),
		rec("passive", 110, nil, []string{"1.1.1.1"}, "", ""),
	}
	// 全量一次性
	engFull := newEngine(t)
	_, _ = engFull.IngestBatch(full)

	// 乱序增量
	engInc := newEngine(t)
	for _, i := range []int{3, 0, 2, 1} {
		_ = engInc.Ingest(full[i])
	}
	// 迟到一条“更旧”的记录
	_ = engInc.Ingest(rec("nmap", 50, []string{"h"}, []string{"1.1.1.1"}, "old-os", "d.com"))
	// 把整批再重复应用两遍
	for _, r := range full {
		_ = engInc.Ingest(r)
	}
	_, _ = engInc.IngestBatch(full)

	got := assetIDs(engInc.Snapshot())
	want := assetIDs(engFull.Snapshot())
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("incremental != full: %v vs %v", got, want)
	}
	a := engInc.Snapshot().ListAssets()[0]
	if a.OS.Value != "R" { // 迟到的更旧记录不得翻转裁决
		t.Fatalf("late old record must not flip winner: %s", a.OS.Value)
	}
	if a.Hostnames[0] != "alias" || len(a.Hostnames) != 2 {
		t.Fatalf("hostnames: %v", a.Hostnames)
	}
}

// 6) 并发摄入：多 goroutine 并行，同一资产只创建一次，无互相覆盖。
func TestConcurrentIngest(t *testing.T) {
	eng := newEngine(t)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				r := rec(fmt.Sprintf("src-%d", g%4), int64(g*100+i),
					[]string{"shared.example.com"}, []string{"10.1.1.1"},
					fmt.Sprintf("os-%d", g), "")
				if err := eng.Ingest(r); err != nil {
					t.Error(err)
					return
				}
			}
		}(g)
	}
	// 并发热查询：任一时刻读到的都是自洽版本
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				snap := eng.Snapshot()
				for _, a := range snap.ListAssets() {
					if a.Services != nil && a.ID == "" {
						t.Error("inconsistent snapshot")
					}
				}
			}
		}
	}()
	wg.Wait()
	close(stop)

	snap := eng.Snapshot()
	if n := len(snap.ListAssets()); n != 1 {
		t.Fatalf("concurrent ingest must converge to one asset, got %d", n)
	}
	a := snap.ListAssets()[0]
	if a.OS.Value == "" || a.OS.Winner.Source == "" {
		t.Fatal("winning attribute must be populated")
	}
}

// 5) 全量重建：重建后清单与增量状态完全一致；重建期间新到变更不丢失。
func TestRebuildEquivalenceAndNoLoss(t *testing.T) {
	eng := newEngine(t)
	base := []model.RawRecord{
		rec("nmap", 1, []string{"h"}, []string{"1.1.1.1"}, "L", "d.com"),
		rec("agent", 2, []string{"h"}, []string{"1.1.1.1"}, "C", "d.com"),
		{Source: "nmap", Timestamp: 3, IPNets: []string{"1.1.1.1"},
			Services: []model.RawService{{Port: 22, Protocol: "tcp", Name: "ssh",
				Creds: []model.RawCredential{{Username: "root", AuthType: "password", Detail: "pw"}}}}},
	}
	_, _ = eng.IngestBatch(base)
	before := assetIDs(eng.Snapshot())
	servicesBefore := eng.Snapshot().ListAssets()[0].Services

	// 重建的同时并发插入新变更（可能发生在持锁前后），最终必须包含它。
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = eng.Rebuild() }()
	go func() {
		defer wg.Done()
		_ = eng.Ingest(rec("cmdb", 4, []string{"h"}, []string{"1.1.1.1"}, "RHEL", "d.com"))
	}()
	wg.Wait()

	snap := eng.Snapshot()
	after := assetIDs(snap)
	if fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("rebuild changed asset set: %v vs %v", before, after)
	}
	a := snap.ListAssets()[0]
	if a.OS.Value != "RHEL" {
		t.Fatalf("change arriving during rebuild must be present: %s", a.OS.Value)
	}
	if _, ok := servicesBefore["tcp/22"]; !ok {
		t.Fatal("service missing before")
	}
	if _, ok := a.Services["tcp/22"]; !ok {
		t.Fatal("service must survive rebuild")
	}
	if len(a.Creds) != 1 {
		t.Fatalf("weak cred relation must survive rebuild: %d", len(a.Creds))
	}
	// 再重建一次结果不变（幂等）
	_ = eng.Rebuild()
	a2 := eng.Snapshot().ListAssets()[0]
	if a2.OS.Value != "RHEL" || len(a2.Creds) != 1 {
		t.Fatal("second rebuild must be equivalent")
	}
}

// 7) 持久化中断恢复：新进程从日志还原后与关闭前完全一致；未完成提交不残留。
func TestRestartRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inv.log")
	cfg := merge.DefaultConfig()

	st, _ := store.NewFileStore(path)
	eng, err := engine.New(engine.Options{MergeConfig: cfg, Store: st})
	if err != nil {
		t.Fatal(err)
	}
	records := []model.RawRecord{
		rec("nmap", 1, []string{"h"}, []string{"1.1.1.1"}, "L", "d.com"),
		rec("cmdb", 2, []string{"h"}, []string{"1.1.1.1"}, "R", "d.com"),
		{Source: "agent", Timestamp: 3, Hostnames: []string{"h"}, IPNets: []string{"1.1.1.1"},
			Services: []model.RawService{{Port: 80, Protocol: "tcp", Name: "http",
				Vulns: []model.RawVuln{{ID: "CVE-1", Title: "t", Severity: "high"}}}}},
	}
	_, _ = eng.IngestBatch(records)
	_ = eng.Rebuild()
	before := dump(eng)
	_ = eng.Close()

	// 重启：重新打开存储并构造引擎
	st2, _ := store.NewFileStore(path)
	eng2, err := engine.New(engine.Options{MergeConfig: cfg, Store: st2})
	if err != nil {
		t.Fatal(err)
	}
	after := dump(eng2)
	if before != after {
		t.Fatalf("recovery mismatch:\nbefore=%s\nafter =%s", before, after)
	}
	// 恢复后继续摄入并再次重启，结果依旧自洽
	_ = eng2.Ingest(rec("agent", 9, []string{"h"}, []string{"1.1.1.1"}, "CentOS9", "d.com"))
	_ = eng2.Close()
	st3, _ := store.NewFileStore(path)
	eng3, _ := engine.New(engine.Options{MergeConfig: cfg, Store: st3})
	a := eng3.Snapshot().ListAssets()[0]
	if a.OS.Value != "R" { // cmdb 仍优先于 agent
		t.Fatalf("post-recovery ingest conflict: %s", a.OS.Value)
	}
	_ = eng3.Close()
}

// dump 生成与版本号无关的快照规范字符串，用于跨重启比对。
func dump(eng *engine.Engine) string {
	s := eng.Snapshot()
	var lines []string
	for _, a := range s.ListAssets() {
		var svcs, vulns, creds []string
		for k := range a.Services {
			svcs = append(svcs, k)
		}
		for k := range a.Vulns {
			vulns = append(vulns, k)
		}
		for k := range a.Creds {
			creds = append(creds, k)
		}
		sort.Strings(svcs)
		sort.Strings(vulns)
		sort.Strings(creds)
		lines = append(lines, strings.Join([]string{
			a.ID,
			strings.Join(a.Hostnames, ","),
			strings.Join(a.IPNets, ","),
			a.OS.Value,
			a.Domain.Value,
			strings.Join(svcs, ","),
			strings.Join(vulns, ","),
			strings.Join(creds, ","),
		}, "|"))
	}
	return strings.Join(lines, "\n")
}
