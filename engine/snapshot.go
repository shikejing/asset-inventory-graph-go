package engine

import (
	"net"
	"sort"
	"strings"

	"github.com/shikejing/asset-inventory-graph-go/graph"
	"github.com/shikejing/asset-inventory-graph-go/model"
)

// Snapshot 是某个已提交版本的只读视图。Asset/Graph 在发布后不再变更，
// 因此所有查询都读取到的是同一个自洽的已提交版本，无需持锁。
type Snapshot struct {
	Version int64
	Assets  map[string]*model.Asset
	Graph   *graph.Graph
}

// GetAsset 按资产 ID（内部 ID 或对外 PrimaryID）查询。
func (s *Snapshot) GetAsset(id string) (*model.Asset, bool) {
	if a, ok := s.Assets[id]; ok {
		return a, true
	}
	for _, a := range s.Assets {
		if a.PrimaryID == id {
			return a, true
		}
	}
	return nil, false
}

// FindByHostname 按主机名查资产（大小写不敏感，去尾点）。
func (s *Snapshot) FindByHostname(name string) (*model.Asset, bool) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	for _, a := range s.Assets {
		for _, h := range a.Hostnames {
			if h == name {
				return a, true
			}
		}
	}
	return nil, false
}

// FindByIP 按 IP 或网段字面量查资产；传入具体 IP 时也会匹配包含它的 CIDR。
func (s *Snapshot) FindByIP(ip string) (*model.Asset, bool) {
	ip = strings.TrimSpace(ip)
	parsed := net.ParseIP(ip)
	for _, a := range s.Assets {
		for _, n := range a.IPNets {
			if n == ip {
				return a, true
			}
			if parsed != nil {
				if _, ipnet, err := net.ParseCIDR(n); err == nil && ipnet.Contains(parsed) {
					return a, true
				}
			}
		}
	}
	return nil, false
}

// ListAssets 返回按 ID 排序的全部资产。
func (s *Snapshot) ListAssets() []*model.Asset {
	out := make([]*model.Asset, 0, len(s.Assets))
	for _, a := range s.Assets {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// AssetRelations 查询资产可达的全部关系节点（环安全遍历）。
func (s *Snapshot) AssetRelations(id string) []string {
	return s.Graph.ReachableFrom("asset:" + id)
}

// DomainAssets 查询归属域下的全部资产（反向边）。
func (s *Snapshot) DomainAssets(domain string) []string {
	nodes := s.Graph.ReverseNeighbors(graph.DomainNodeID(domain))
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, strings.TrimPrefix(n, "asset:"))
	}
	sort.Strings(out)
	return out
}

// Stats 返回图统计信息（环安全）。
type Stats struct {
	AssetCount   int
	ServiceCount int
	VulnCount    int
	CredCount    int
	DomainCount  int
	EdgeCount    int
	Cycles       int
}

// Stats 统计节点、边与环数量。
func (s *Snapshot) Stats() Stats {
	cnt := s.Graph.CountByKind()
	return Stats{
		AssetCount:   cnt[graph.NodeAsset],
		ServiceCount: cnt[graph.NodeService],
		VulnCount:    cnt[graph.NodeVuln],
		CredCount:    cnt[graph.NodeCred],
		DomainCount:  cnt[graph.NodeDomain],
		EdgeCount:    len(s.Graph.Edges),
		Cycles:       s.Graph.CycleCount(),
	}
}
