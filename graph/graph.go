package graph

import (
	"sort"

	"github.com/shikejing/asset-inventory-graph-go/model"
)

// NodeKind 描述关系图节点类型。
type NodeKind string

const (
	NodeAsset   NodeKind = "asset"
	NodeService NodeKind = "service"
	NodeVuln    NodeKind = "vuln"
	NodeCred    NodeKind = "weakcred"
	NodeDomain  NodeKind = "domain"
)

// Graph 是资产关系图。所有遍历均以 visited 集合驱动，天然环安全。
type Graph struct {
	Assets  map[string]*model.Asset
	Kind    map[string]NodeKind
	Adj     map[string][]string // 正向邻接（有序）
	Rev     map[string][]string // 反向邻接（有序）
	Edges   []model.Edge
	edgeSet map[string]bool
}

// Builder 负责从资产集合构建关系图。
type Builder struct{}

func NewBuilder() *Builder { return &Builder{} }

func edgeKey(e model.Edge) string { return string(e.Kind) + "|" + e.From + "->" + e.To }

func (g *Graph) addEdge(e model.Edge) {
	if g.edgeSet == nil {
		g.edgeSet = map[string]bool{}
	}
	k := edgeKey(e)
	if g.edgeSet[k] {
		return
	}
	g.edgeSet[k] = true
	g.Edges = append(g.Edges, e)
	g.Adj[e.From] = append(g.Adj[e.From], e.To)
	g.Rev[e.To] = append(g.Rev[e.To], e.From)
}

// ServiceNodeID 返回服务节点 ID。
func ServiceNodeID(assetID, svcKey string) string { return "svc:" + assetID + ":" + svcKey }

// VulnNodeID 返回漏洞节点 ID。
func VulnNodeID(id string) string { return id }

// CredNodeID 返回弱口令节点 ID。
func CredNodeID(id string) string { return id }

// DomainNodeID 返回归属域节点 ID。
func DomainNodeID(domain string) string { return "dom:" + domain }

// Build 根据资产清单构建关系图。每次提交重新构建，保证资产更新后关系自洽。
func (b *Builder) Build(assets map[string]*model.Asset) *Graph {
	g := &Graph{
		Assets: assets,
		Kind:   map[string]NodeKind{},
		Adj:    map[string][]string{},
		Rev:    map[string][]string{},
	}
	assetIDs := make([]string, 0, len(assets))
	for id := range assets {
		assetIDs = append(assetIDs, id)
	}
	sort.Strings(assetIDs)

	for _, aid := range assetIDs {
		a := assets[aid]
		an := "asset:" + aid
		g.Kind[an] = NodeAsset
		g.Adj[an] = nil
		if d := a.Domain.Value; d != "" {
			dn := DomainNodeID(d)
			g.Kind[dn] = NodeDomain
			g.addEdge(model.Edge{From: an, To: dn, Kind: model.EdgeAssetDomain})
		}
		for _, vid := range sortedVulnKeys(a.Vulns) {
			vn := VulnNodeID(vid)
			g.Kind[vn] = NodeVuln
			g.addEdge(model.Edge{From: an, To: vn, Kind: model.EdgeAssetVuln})
		}
		svcKeys := make([]string, 0, len(a.Services))
		for k := range a.Services {
			svcKeys = append(svcKeys, k)
		}
		sort.Strings(svcKeys)
		for _, sk := range svcKeys {
			s := a.Services[sk]
			sn := ServiceNodeID(aid, sk)
			g.Kind[sn] = NodeService
			g.addEdge(model.Edge{From: an, To: sn, Kind: model.EdgeAssetService})
			for _, vid := range s.VulnIDs {
				g.Kind[vid] = NodeVuln
				g.addEdge(model.Edge{From: sn, To: vid, Kind: model.EdgeServiceVuln})
			}
			for _, cid := range s.CredIDs {
				cn := CredNodeID(cid)
				g.Kind[cn] = NodeCred
				g.addEdge(model.Edge{From: sn, To: cn, Kind: model.EdgeServiceCred})
			}
		}
	}
	for n := range g.Adj {
		sort.Strings(g.Adj[n])
	}
	for n := range g.Rev {
		sort.Strings(g.Rev[n])
	}
	sort.Slice(g.Edges, func(i, j int) bool { return edgeKey(g.Edges[i]) < edgeKey(g.Edges[j]) })
	return g
}

func sortedVulnKeys(m map[string]*model.Vuln) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Neighbors 返回节点的直接邻居。
func (g *Graph) Neighbors(node string) []string {
	out := append([]string{}, g.Adj[node]...)
	return out
}

// ReverseNeighbors 返回指向该节点的节点（例如域下的全部资产）。
func (g *Graph) ReverseNeighbors(node string) []string {
	return append([]string{}, g.Rev[node]...)
}

// ReachableFrom 从某节点出发做环安全的可达性遍历（visited 去重，不死循环）。
func (g *Graph) ReachableFrom(node string) []string {
	seen := map[string]bool{}
	stack := []string{node}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[n] {
			continue
		}
		seen[n] = true
		for _, nb := range g.Adj[n] {
			if !seen[nb] {
				stack = append(stack, nb)
			}
		}
	}
	delete(seen, node)
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// DetectCycle 返回图中发现的一条环（节点序列，首尾相同）；无环返回 nil。
func (g *Graph) DetectCycle() []string {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	parent := map[string]string{}
	nodes := make([]string, 0, len(g.Adj))
	for n := range g.Adj {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	var cycle []string
	var dfs func(n string) bool
	dfs = func(n string) bool {
		color[n] = gray
		for _, nb := range g.Adj[n] {
			if color[nb] == white {
				parent[nb] = n
				if dfs(nb) {
					return true
				}
			} else if color[nb] == gray {
				// 还原环：nb ... n -> nb
				path := []string{n}
				for x := n; x != nb && parent[x] != ""; x = parent[x] {
					path = append(path, parent[x])
					if parent[x] == nb {
						break
					}
				}
				// path 从 n 向祖先方向；反转为 nb -> ... -> n
				for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
					path[i], path[j] = path[j], path[i]
				}
				path = append(path, nb)
				cycle = path
				return true
			}
		}
		color[n] = black
		return false
	}
	for _, n := range nodes {
		if color[n] == white {
			if dfs(n) {
				return cycle
			}
		}
	}
	return nil
}

// CycleCount 统计图中不同回边的数量（环安全统计）。
func (g *Graph) CycleCount() int {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	count := 0
	nodes := make([]string, 0, len(g.Adj))
	for n := range g.Adj {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	var dfs func(n string)
	dfs = func(n string) {
		color[n] = gray
		for _, nb := range g.Adj[n] {
			switch color[nb] {
			case white:
				dfs(nb)
			case gray:
				count++
			}
		}
		color[n] = black
	}
	for _, n := range nodes {
		if color[n] == white {
			dfs(n)
		}
	}
	return count
}

// CountByKind 按节点类型统计。
func (g *Graph) CountByKind() map[NodeKind]int {
	out := map[NodeKind]int{}
	for _, k := range g.Kind {
		out[k]++
	}
	return out
}
