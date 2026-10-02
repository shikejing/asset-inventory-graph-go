package inventory

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// buildGraph constructs the relationship graph from converged assets and the
// identity index. It returns the graph and the identity-key -> asset-id map.
func buildGraph(assets map[string]*Asset, idx *identityIndex, finalID map[string]string) (*Graph, map[string]string) {
	g := &Graph{
		Nodes: map[string]*Node{},
		adj:   map[string][]Edge{},
		in:    map[string][]Edge{},
	}
	addNode := func(kind NodeKind, id, name string, meta map[string]string) string {
		if n, ok := g.Nodes[id]; ok {
			return n.ID
		}
		g.Nodes[id] = &Node{Kind: kind, ID: id, Name: name, Meta: meta}
		return id
	}
	addEdge := func(from, to string, kind EdgeKind) {
		e := Edge{From: from, To: to, Kind: kind}
		g.Edges = append(g.Edges, e)
	}

	// identity key -> final asset id, for dependency resolution.
	keyToAsset := map[string]string{}
	for comp, keys := range idx.compKeys {
		aid := finalID[comp]
		for k := range keys {
			keyToAsset[k] = aid
		}
	}

	assetIDs := make([]string, 0, len(assets))
	for id := range assets {
		assetIDs = append(assetIDs, id)
	}
	sort.Strings(assetIDs)

	for _, aid := range assetIDs {
		a := assets[aid]
		name := a.Hostname
		if name == "" && len(a.IPs) > 0 {
			name = a.IPs[0]
		}
		addNode(NodeAsset, aid, name, map[string]string{"os": a.OS, "domain": a.Domain})

		if a.Domain != "" {
			did := "domain:" + a.Domain
			addNode(NodeDomain, did, a.Domain, nil)
			addEdge(aid, did, EdgeBelongsTo)
		}

		for _, svc := range a.Services {
			sid := fmt.Sprintf("svc:%s:%s:%d", aid, svc.Name, svc.Port)
			meta := map[string]string{}
			if svc.Version != "" {
				meta["version"] = svc.Version
			}
			if svc.Protocol != "" {
				meta["protocol"] = svc.Protocol
			}
			addNode(NodeService, sid, fmt.Sprintf("%s:%d", svc.Name, svc.Port), meta)
			addEdge(aid, sid, EdgeRuns)

			for _, wp := range svc.WeakPasswords {
				wid := "wp:" + shortHash(sid+"|"+wp)
				addNode(NodeWeakPassword, wid, wp, nil)
				addEdge(sid, wid, EdgeHasWeakPassword)
			}
			for _, vuln := range svc.Vulnerabilities {
				vid := "vuln:" + vuln
				addNode(NodeVulnerability, vid, vuln, nil)
				addEdge(sid, vid, EdgeHasVulnerability)
			}
		}
	}

	// Dependency edges: resolve identity keys against the index.
	for _, aid := range assetIDs {
		a := assets[aid]
		for _, dep := range a.depends {
			target := resolveIdentity(dep)
			if tid, ok := keyToAsset[target]; ok && tid != aid {
				addEdge(aid, tid, EdgeDependsOn)
			}
		}
	}

	// Deterministic edge ordering, then build adjacency.
	sort.Slice(g.Edges, func(i, j int) bool {
		if g.Edges[i].From != g.Edges[j].From {
			return g.Edges[i].From < g.Edges[j].From
		}
		if g.Edges[i].To != g.Edges[j].To {
			return g.Edges[i].To < g.Edges[j].To
		}
		return g.Edges[i].Kind < g.Edges[j].Kind
	})
	for _, e := range g.Edges {
		g.adj[e.From] = append(g.adj[e.From], e)
		g.in[e.To] = append(g.in[e.To], e)
	}
	return g, keyToAsset
}

// resolveIdentity normalizes a dependency reference to an identity key.
func resolveIdentity(ref string) string {
	ref = strings.TrimSpace(ref)
	if ip, ok := NormalizeIP(ref); ok {
		return "ip:" + ip
	}
	return "hn:" + NormalizeHostname(ref)
}

func shortHash(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])[:16]
}

// ---- graph queries ----

// Direction selects edge direction for traversal.
type Direction int

const (
	// DirOut follows edges from the node to its neighbors.
	DirOut Direction = iota
	// DirIn follows edges pointing to the node.
	DirIn
	// DirBoth follows edges in both directions.
	DirBoth
)

// Neighbors returns the nodes directly connected to nodeID via edges of the
// given kind (kind == "" means any kind), in the requested direction.
func (g *Graph) Neighbors(nodeID string, kind EdgeKind, dir Direction) []*Node {
	if g == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []*Node
	collect := func(edges []Edge) {
		for _, e := range edges {
			if kind != "" && e.Kind != kind {
				continue
			}
			other := e.To
			if dir == DirIn {
				other = e.From
			}
			if seen[other] {
				continue
			}
			seen[other] = true
			if n, ok := g.Nodes[other]; ok {
				out = append(out, n)
			}
		}
	}
	switch dir {
	case DirOut:
		collect(g.adj[nodeID])
	case DirIn:
		collect(g.in[nodeID])
	default:
		collect(g.adj[nodeID])
		collect(g.in[nodeID])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ReachNode is a node reached during graph traversal with its hop depth.
type ReachNode struct {
	Node  *Node
	Depth int
}

// Reachable performs a cycle-safe breadth-first traversal starting at
// nodeID up to maxDepth hops (maxDepth < 0 means unlimited). Cycles never
// cause infinite loops: every node is visited at most once.
func (g *Graph) Reachable(nodeID string, maxDepth int) []ReachNode {
	if g == nil {
		return nil
	}
	visited := map[string]bool{nodeID: true}
	queue := []ReachNode{{Node: g.Nodes[nodeID], Depth: 0}}
	if g.Nodes[nodeID] == nil {
		return nil
	}
	var out []ReachNode
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		out = append(out, cur)
		if maxDepth >= 0 && cur.Depth >= maxDepth {
			continue
		}
		for _, e := range g.adj[cur.Node.ID] {
			if visited[e.To] {
				continue
			}
			visited[e.To] = true
			if n, ok := g.Nodes[e.To]; ok {
				queue = append(queue, ReachNode{Node: n, Depth: cur.Depth + 1})
			}
		}
	}
	return out
}

// GraphStats summarizes the graph.
type GraphStats struct {
	Nodes       int
	Edges       int
	NodesByKind map[NodeKind]int
	EdgesByKind map[EdgeKind]int
}

// Stats returns node/edge counts broken down by kind.
func (g *Graph) Stats() GraphStats {
	s := GraphStats{
		Nodes:       len(g.Nodes),
		Edges:       len(g.Edges),
		NodesByKind: map[NodeKind]int{},
		EdgesByKind: map[EdgeKind]int{},
	}
	for _, n := range g.Nodes {
		s.NodesByKind[n.Kind]++
	}
	for _, e := range g.Edges {
		s.EdgesByKind[e.Kind]++
	}
	return s
}
