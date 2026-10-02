package engine

import (
	"sort"
	"sync"
	"sync/atomic"

	"github.com/shikejing/asset-inventory-graph-go/graph"
	"github.com/shikejing/asset-inventory-graph-go/merge"
	"github.com/shikejing/asset-inventory-graph-go/model"
	"github.com/shikejing/asset-inventory-graph-go/normalize"
	"github.com/shikejing/asset-inventory-graph-go/store"
)

// Engine 是资产清单引擎：
//   - 多来源并发摄入：提交期串行化，保证同一资产不重复创建、不互相覆盖；
//   - 查询走已发布快照的原子指针，慢来源 fsync 不阻塞查询推进；
//   - 每次提交都从全量观察确定性重算，天然支持乱序/重复/迟到与全量重建；
//   - 提交顺序“先持久化、后发布”，崩溃后由日志完整恢复，无半写状态。
type Engine struct {
	mu     sync.Mutex
	norm   *normalize.Normalizer
	merger *merge.Merger
	bld    *graph.Builder
	st     store.Store

	records []store.ObservationRecord // 已提交观察（内容幂等）
	seen    map[string]bool
	version int64
	snap    atomic.Pointer[Snapshot]
}

// Options 是引擎构造参数。
type Options struct {
	MergeConfig merge.Config
	Store       store.Store
}

// New 构造引擎；若 Store 中存在已提交记录则执行恢复还原。
func New(opts Options) (*Engine, error) {
	e := &Engine{
		norm:   normalize.NewNormalizer(),
		merger: merge.NewMerger(opts.MergeConfig),
		bld:    graph.NewBuilder(),
		st:     opts.Store,
		seen:   map[string]bool{},
	}
	if e.st != nil {
		recs, err := e.st.Load()
		if err != nil {
			return nil, err
		}
		e.records = append(e.records, recs...)
		for _, r := range recs {
			e.seen[r.DedupKey] = true
		}
	}
	e.rematerializeLocked()
	return e, nil
}

// Ingest 幂等应用一条扫描记录。重复/乱序/迟到都不会让清单偏离全量结果。
func (e *Engine) Ingest(r model.RawRecord) error {
	obs, err := e.norm.Normalize(r)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.seen[obs.DedupKey] {
		return nil
	}
	rec := store.ObservationRecord{DedupKey: obs.DedupKey, Record: r}
	if e.st != nil { // 先持久化，fsync 成功才算提交
		if err := e.st.Append([]store.ObservationRecord{rec}); err != nil {
			return err
		}
	}
	e.records = append(e.records, rec)
	e.seen[obs.DedupKey] = true
	e.rematerializeLocked()
	return nil
}

// IngestBatch 批量提交一批记录（一次日志原子追加），返回实际新提交条数。
func (e *Engine) IngestBatch(rs []model.RawRecord) (int, error) {
	type prepared struct {
		rec store.ObservationRecord
		key string
	}
	ps := make([]prepared, 0, len(rs))
	for _, r := range rs {
		obs, err := e.norm.Normalize(r)
		if err != nil {
			return 0, err
		}
		ps = append(ps, prepared{store.ObservationRecord{DedupKey: obs.DedupKey, Record: r}, obs.DedupKey})
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	fresh := make([]store.ObservationRecord, 0, len(ps))
	for _, p := range ps {
		if e.seen[p.key] {
			continue
		}
		e.seen[p.key] = true
		fresh = append(fresh, p.rec)
	}
	if len(fresh) == 0 {
		return 0, nil
	}
	if e.st != nil {
		if err := e.st.Append(fresh); err != nil {
			for _, r := range fresh { // 追加失败：撤销预占，可安全重试
				delete(e.seen, r.DedupKey)
			}
			return 0, err
		}
	}
	e.records = append(e.records, fresh...)
	e.rematerializeLocked()
	return len(fresh), nil
}

// Rebuild 全量重建：压实日志并从全部观察从零重算。
// 持锁期间到达的摄入阻塞等待，重建完成后依次应用，变更不丢失；
// 合并是确定性的，最终状态等价于把全部记录（含等待中的新到达）一次性全量重放。
func (e *Engine) Rebuild() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.st != nil {
		if err := e.st.ReplaceAll(e.records); err != nil { // temp+fsync+rename 原子替换
			return err
		}
	}
	e.seen = map[string]bool{}
	for _, r := range e.records {
		e.seen[r.DedupKey] = true
	}
	e.rematerializeLocked()
	return nil
}

// Snapshot 返回当前已提交版本（原子读取，无锁，慢来源不阻塞查询）。
func (e *Engine) Snapshot() *Snapshot {
	s := e.snap.Load()
	if s == nil {
		return &Snapshot{Assets: map[string]*model.Asset{}, Graph: graph.NewBuilder().Build(nil)}
	}
	return s
}

// Version 返回当前已提交版本号。
func (e *Engine) Version() int64 { return e.Snapshot().Version }

// Close 持久化并关闭。
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.st != nil {
		return e.st.Close()
	}
	return nil
}

// agg 是重算期间单个资产（标识组件）的累加器。
type agg struct {
	id        string
	ipnets    []model.Provenance
	hostnames []model.Provenance
	os        []model.Provenance
	domain    []model.Provenance
	services  map[string][]model.RawService
	vulns     []model.RawVuln
}

// rematerializeLocked 从全部已提交观察确定性重算资产清单与关系图。
func (e *Engine) rematerializeLocked() {
	e.version++
	uf := normalize.NewUnionFind()
	obsList := make([]*normalize.Observation, 0, len(e.records))
	for _, rec := range e.records {
		obs, err := e.norm.Normalize(rec.Record)
		if err != nil {
			continue
		}
		obsList = append(obsList, obs)
		uf.UnionAll(obs.IDs)
	}

	aggs := map[string]*agg{}
	getAgg := func(root string) *agg {
		a := aggs[root]
		if a == nil {
			a = &agg{id: root, services: map[string][]model.RawService{}}
			aggs[root] = a
		}
		return a
	}

	for _, obs := range obsList {
		if len(obs.IDs) == 0 {
			continue // 无任何稳定标识的观察无法形成资产身份
		}
		root := uf.Find(obs.IDs[0])
		a := getAgg(root)
		for _, v := range obs.IPNets {
			a.ipnets = append(a.ipnets, model.Provenance{Source: obs.Source, Timestamp: obs.Timestamp, Value: v})
		}
		for _, v := range obs.Hostnames {
			a.hostnames = append(a.hostnames, model.Provenance{Source: obs.Source, Timestamp: obs.Timestamp, Value: v})
		}
		if obs.OS != "" {
			a.os = append(a.os, model.Provenance{Source: obs.Source, Timestamp: obs.Timestamp, Value: obs.OS})
		}
		if obs.Domain != "" {
			a.domain = append(a.domain, model.Provenance{Source: obs.Source, Timestamp: obs.Timestamp, Value: obs.Domain})
		}
		for _, s := range obs.Services {
			key := normalize.ServiceKey(s.Port, s.Protocol)
			a.services[key] = append(a.services[key], s)
		}
		a.vulns = append(a.vulns, obs.Vulns...)
	}

	assets := map[string]*model.Asset{}
	roots := sortedKeys(aggs)
	for _, root := range roots {
		a := aggs[root]
		members := uf.Members(root)
		asset := &model.Asset{
			ID:        root,
			PrimaryID: members[0],
			Services:  map[string]*model.Service{},
			Vulns:     map[string]*model.Vuln{},
			Creds:     map[string]*model.WeakCred{},
			Lists:     map[string][]model.ValueProvenance{},
			Version:   e.version,
		}
		asset.Lists["ipnets"] = e.merger.MergeSet("ipnets", a.ipnets)
		asset.Lists["hostnames"] = e.merger.MergeSet("hostnames", a.hostnames)
		asset.IPNets = valuesOf(asset.Lists["ipnets"])
		asset.Hostnames = valuesOf(asset.Lists["hostnames"])
		asset.OS = e.merger.MergeScalar("os", a.os)
		asset.Domain = e.merger.MergeScalar("domain", a.domain)

		for _, sk := range sortedServiceKeys(a.services) {
			svcs := a.services[sk]
			svc := &model.Service{Key: sk, Attrs: map[string]model.Attribute{}}
			svc.Port = svcs[0].Port
			svc.Protocol = svcs[0].Protocol
			if svc.Protocol == "" {
				svc.Protocol = "tcp"
			}
			var names, versions, products, banners []model.Provenance
			vulnSeen := map[string]bool{}
			credSeen := map[string]model.RawCredential{}
			for _, s := range svcs {
				if s.Name != "" {
					names = append(names, model.Provenance{Source: s.Source, Timestamp: s.Timestamp, Value: s.Name})
				}
				if s.Version != "" {
					versions = append(versions, model.Provenance{Source: s.Source, Timestamp: s.Timestamp, Value: s.Version})
				}
				if s.Product != "" {
					products = append(products, model.Provenance{Source: s.Source, Timestamp: s.Timestamp, Value: s.Product})
				}
				if s.Banner != "" {
					banners = append(banners, model.Provenance{Source: s.Source, Timestamp: s.Timestamp, Value: s.Banner})
				}
				for _, v := range s.Vulns {
					vid := normalize.VulnID(v)
					vulnSeen[vid] = true
				}
				for _, c := range s.Creds {
					cid := normalize.CredID(svc.Port, c)
					if _, ok := credSeen[cid]; !ok {
						credSeen[cid] = c
					}
				}
			}
			svc.Attrs["svc.name"] = e.merger.MergeScalar("svc.name", names)
			svc.Attrs["svc.version"] = e.merger.MergeScalar("svc.version", versions)
			svc.Attrs["svc.product"] = e.merger.MergeScalar("svc.product", products)
			svc.Attrs["svc.banner"] = e.merger.MergeScalar("svc.banner", banners)
			svc.Name = svc.Attrs["svc.name"].Value
			svc.Version = svc.Attrs["svc.version"].Value
			svc.Product = svc.Attrs["svc.product"].Value
			svc.Banner = svc.Attrs["svc.banner"].Value
			svc.VulnIDs = sortedSet(vulnSeen)
			for _, cid := range sortedCredKeys(credSeen) {
				svc.CredIDs = append(svc.CredIDs, cid)
			}
			asset.Services[sk] = svc
		}

		// 漏洞节点：同 ID 合并，标题/严重度按来源优先级裁决并可追溯。
		vulnGroup := map[string][]model.RawVuln{}
		for _, v := range a.vulns {
			vulnGroup[normalize.VulnID(v)] = append(vulnGroup[normalize.VulnID(v)], v)
		}
		for _, vid := range sortedVulnGroups(vulnGroup) {
			vs := vulnGroup[vid]
			var titleP, sevP []model.Provenance
			for _, v := range vs {
				if v.Title != "" {
					titleP = append(titleP, model.Provenance{Source: v.Source, Timestamp: v.Timestamp, Value: v.Title})
				}
				if v.Severity != "" {
					sevP = append(sevP, model.Provenance{Source: v.Source, Timestamp: v.Timestamp, Value: v.Severity})
				}
			}
			ta := e.merger.MergeScalar("vuln.title", titleP)
			sa := e.merger.MergeScalar("vuln.severity", sevP)
			asset.Vulns[vid] = &model.Vuln{
				ID: vid, Title: ta.Value, Severity: sa.Value,
				Source: ta.Winner.Source, Attributes: map[string]string{},
			}
		}

		// 弱口令节点：从服务观察提取（内容寻址 ID 天然幂等去重）。
		credGroup := map[string]model.RawCredential{}
		for _, sk := range sortedServiceKeys(a.services) {
			port := a.services[sk][0].Port
			for _, s := range a.services[sk] {
				for _, c := range s.Creds {
					cid := normalize.CredID(port, c)
					if _, ok := credGroup[cid]; !ok {
						credGroup[cid] = c
					}
				}
			}
		}
		for _, cid := range sortedCredGroups(credGroup) {
			c := credGroup[cid]
			port := c.ServicePort
			if port == 0 {
				port = svcPortOf(a.services, cid)
			}
			asset.Creds[cid] = &model.WeakCred{
				ID: cid, Port: port, Username: c.Username,
				AuthType: c.AuthType, Detail: c.Detail, Source: c.Source,
			}
		}

		assets[root] = asset
	}

	g := e.bld.Build(assets)
	e.snap.Store(&Snapshot{Version: e.version, Assets: assets, Graph: g})
}

func valuesOf(vps []model.ValueProvenance) []string {
	out := make([]string, 0, len(vps))
	for _, vp := range vps {
		out = append(out, vp.Value)
	}
	return out
}

func sortedKeys(m map[string]*agg) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedServiceKeys(m map[string][]model.RawService) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedVulnGroups(m map[string][]model.RawVuln) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedCredKeys(m map[string]model.RawCredential) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedCredGroups(m map[string]model.RawCredential) []string {
	return sortedCredKeys(m)
}

// svcPortOf 弱口令节点 ID 形如 cred:<port>/<hash>，从中还原端口。
func svcPortOf(services map[string][]model.RawService, cid string) int {
	for _, svcs := range services {
		port := svcs[0].Port
		if cid == normalize.CredID(port, model.RawCredential{}) {
			continue
		}
		for _, s := range svcs {
			for _, c := range s.Creds {
				if normalize.CredID(port, c) == cid {
					return port
				}
			}
		}
	}
	return 0
}
