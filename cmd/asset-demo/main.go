package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/shikejing/asset-inventory-graph-go/engine"
	"github.com/shikejing/asset-inventory-graph-go/merge"
	"github.com/shikejing/asset-inventory-graph-go/model"
	"github.com/shikejing/asset-inventory-graph-go/source"
	"github.com/shikejing/asset-inventory-graph-go/store"
)

func main() {
	dbPath := flag.String("db", "asset-inventory.log", "持久化日志路径")
	reset := flag.Bool("reset", false, "启动前清空历史日志")
	flag.Parse()

	if *reset {
		_ = os.Remove(*dbPath)
	}

	st, err := store.NewFileStore(*dbPath)
	must(err)

	cfg := merge.DefaultConfig()
	eng, err := engine.New(engine.Options{MergeConfig: cfg, Store: st})
	must(err)

	// 1) 三个内存来源覆盖同一资产（字段互相矛盾），其中一个是慢来源。
	nmap := source.NewSimSource("nmap", []model.RawRecord{
		{
			Source: "nmap", Timestamp: 100,
			Hostnames: []string{"web-01.example.com"},
			IPNets:    []string{"10.0.0.5"},
			OS:        "Linux 3.x",
			Services: []model.RawService{
				{Port: 22, Protocol: "tcp", Name: "ssh", Version: "OpenSSH 7.4"},
				{Port: 80, Protocol: "tcp", Name: "http", Product: "nginx",
					Vulns: []model.RawVuln{{ID: "CVE-2019-0001", Title: "nginx info leak", Severity: "medium"}}},
			},
			Domain: "example.com",
		},
	})
	agent := source.NewSimSource("agent", []model.RawRecord{
		{
			Source: "agent", Timestamp: 90,
			Hostnames: []string{"web-01.example.com"},
			IPNets:    []string{"10.0.0.5"},
			OS:        "CentOS 7 (Linux 3.10)",
			Domain:    "example.com",
			Services: []model.RawService{
				{Port: 22, Protocol: "tcp", Name: "ssh", Version: "OpenSSH 7.4p1",
					Creds: []model.RawCredential{{Username: "root", AuthType: "password", Detail: "123456"}}},
			},
		},
	})
	passive := source.NewSimSource("passivescan", []model.RawRecord{
		{
			Source: "passivescan", Timestamp: 110,
			IPNets: []string{"10.0.0.5", "10.0.0.0/24"},
			Services: []model.RawService{
				{Port: 443, Protocol: "tcp", Name: "https"},
			},
		},
	}).WithDelay(60 * time.Millisecond) // 慢来源：不阻塞其它来源摄入与查询

	runner := source.NewRunner(eng)
	must(runner.Run(context.Background(), []source.Source{nmap, agent, passive}))

	// 2) 本地回环来源再补一条迟到记录（同一资产的另一个主机名别名）。
	srv, err := source.NewLoopbackServer(0)
	must(err)
	// 先开始消费，再由回环连接推送；推送结束后空闲 200ms 该来源自动收尾。
	runErr := make(chan error, 1)
	go func() { runErr <- runner.Run(context.Background(), []source.Source{idleSource{srv}}) }()
	time.Sleep(50 * time.Millisecond)
	err = source.SendLoopback(srv.Addr(), []model.RawRecord{{
		Source: "cmdb", Timestamp: 120,
		Hostnames: []string{"web-01.example.com", "web.example.com"},
		IPNets:    []string{"10.0.0.5"},
		OS:        "RHEL 7",
		Domain:    "example.com",
	}})
	must(err)
	must(<-runErr)
	_ = srv.Close()

	// 3) 乱序/重复幂等：把已提交过的整批记录再应用一遍，结论必须不变（版本不增加）。
	before := eng.Version()
	n, _ := eng.IngestBatch([]model.RawRecord{
		{Source: "nmap", Timestamp: 100,
			Hostnames: []string{"web-01.example.com"}, IPNets: []string{"10.0.0.5"}, OS: "Linux 3.x",
			Services: []model.RawService{
				{Port: 22, Protocol: "tcp", Name: "ssh", Version: "OpenSSH 7.4"},
				{Port: 80, Protocol: "tcp", Name: "http", Product: "nginx",
					Vulns: []model.RawVuln{{ID: "CVE-2019-0001", Title: "nginx info leak", Severity: "medium"}}},
			},
			Domain: "example.com"},
		{Source: "passivescan", Timestamp: 110, IPNets: []string{"10.0.0.5", "10.0.0.0/24"},
			Services: []model.RawService{{Port: 443, Protocol: "tcp", Name: "https"}}},
	})
	if n != 0 || eng.Version() != before {
		fmt.Println("WARN: 重复批次产生了新结论")
	}

	// 4) 全量重建（压实日志），结果对齐变更流。
	must(eng.Rebuild())

	printSnapshot(eng)

	must(eng.Close())
	fmt.Println("已持久化，重启后将从日志完整还原（去掉 -reset 再运行可验证恢复）。")
}

func printSnapshot(eng *engine.Engine) {
	snap := eng.Snapshot()
	st := snap.Stats()
	fmt.Printf("v%d 资产=%d 服务=%d 漏洞=%d 弱口令=%d 域=%d 边=%d 环=%d\n",
		snap.Version, st.AssetCount, st.ServiceCount, st.VulnCount,
		st.CredCount, st.DomainCount, st.EdgeCount, st.Cycles)
	for _, a := range snap.ListAssets() {
		fmt.Printf("- 资产 %s (primary=%s)\n", a.ID, a.PrimaryID)
		fmt.Printf("    主机名=%v 网段=%v\n", a.Hostnames, a.IPNets)
		fmt.Printf("    OS=%q 依据=%s\n", a.OS.Value, formatHistory(a.OS.History))
		fmt.Printf("    归属域=%q 依据=%s\n", a.Domain.Value, formatHistory(a.Domain.History))
		for key, sv := range a.Services {
			fmt.Printf("    服务 %s name=%q(%s) version=%q(%s)\n",
				key, sv.Name, sv.Attrs["svc.name"].Winner.Source,
				sv.Version, sv.Attrs["svc.version"].Winner.Source)
		}
		fmt.Printf("    关系: %v\n", snap.AssetRelations(a.ID))
	}
}

func formatHistory(h []model.Provenance) string {
	s := ""
	for i, p := range h {
		if i > 0 {
			s += " < "
		}
		s += fmt.Sprintf("%s@%d=%q", p.Source, p.Timestamp, p.Value)
	}
	return s
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

// idleSource 包装回环服务器，使其在推送结束后空闲 200ms 自动结束流。
type idleSource struct{ *source.LoopbackServer }

func (i idleSource) Records(ctx context.Context) <-chan model.RawRecord {
	return i.LoopbackServer.Records(ctx, 200*time.Millisecond)
}
