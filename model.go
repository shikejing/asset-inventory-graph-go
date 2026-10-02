package inventory

import "time"

// SourceID identifies a scanning source.
type SourceID string

// RawRecord is a raw asset observation produced by a scanning source.
// It is the unit of ingestion and the unit of idempotency: records with
// the same ID are considered the same observation.
type RawRecord struct {
	ID        string    `json:"id"`
	Source    SourceID  `json:"source"`
	Seq       int64     `json:"seq"`
	Timestamp time.Time `json:"timestamp"`

	// Identity claims: these attributes are used to decide whether two
	// observations refer to the same asset (stable identifier convergence).
	Hostname string   `json:"hostname,omitempty"`
	IPs      []string `json:"ips,omitempty"`
	MACs     []string `json:"macs,omitempty"`

	// Descriptive attributes.
	Domain   string            `json:"domain,omitempty"`
	OS       string            `json:"os,omitempty"`
	Ports    []int             `json:"ports,omitempty"`
	Services []ServiceObs      `json:"services,omitempty"`
	Attrs    map[string]string `json:"attrs,omitempty"`

	// DependsOn contains identity keys (hostname / IP) of assets this asset
	// depends on. Edges are resolved against the identity index.
	DependsOn []string `json:"depends_on,omitempty"`
}

// ServiceObs is a service observation attached to a raw record.
type ServiceObs struct {
	Name            string   `json:"name"`
	Port            int      `json:"port"`
	Protocol        string   `json:"protocol,omitempty"`
	Version         string   `json:"version,omitempty"`
	WeakPasswords   []string `json:"weak_passwords,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
}

// ValueEvidence is a single observed value of an attribute together with
// the source that provided it. Conflicts always retain all evidence.
type ValueEvidence struct {
	Source    SourceID  `json:"source"`
	Value     string    `json:"value"`
	Timestamp time.Time `json:"timestamp"`
	RecordID  string    `json:"record_id"`
}

// Conflict records a single-attribute merge decision where sources disagreed.
// Nothing is silently dropped: all candidates and the winner are retained.
type Conflict struct {
	Attr       string          `json:"attr"`
	Chosen     string          `json:"chosen"`
	ChosenSrc  SourceID        `json:"chosen_source"`
	Reason     string          `json:"reason"`
	Candidates []ValueEvidence `json:"candidates"`
}

// Service is the merged view of a service across sources.
type Service struct {
	Name            string          `json:"name"`
	Port            int             `json:"port"`
	Protocol        string          `json:"protocol,omitempty"`
	Version         string          `json:"version,omitempty"`
	VersionEvidence []ValueEvidence `json:"version_evidence,omitempty"`
	WeakPasswords   []string        `json:"weak_passwords,omitempty"`
	Vulnerabilities []string        `json:"vulnerabilities,omitempty"`
	Sources         []SourceID      `json:"sources,omitempty"`
}

// Asset is the converged, unique view of an asset.
type Asset struct {
	ID       string            `json:"id"`
	Hostname string            `json:"hostname,omitempty"`
	IPs      []string          `json:"ips,omitempty"`
	MACs     []string          `json:"macs,omitempty"`
	Domain   string            `json:"domain,omitempty"`
	OS       string            `json:"os,omitempty"`
	Ports    []int             `json:"ports,omitempty"`
	Services []Service         `json:"services,omitempty"`
	Attrs    map[string]string `json:"attrs,omitempty"`

	Conflicts []Conflict                 `json:"conflicts,omitempty"`
	Evidence  map[string][]ValueEvidence `json:"evidence,omitempty"`
	Sources   []SourceID                 `json:"sources,omitempty"`
	RecordIDs []string                   `json:"record_ids,omitempty"`

	// depends holds raw dependency identity keys; rebuilt from records.
	depends []string

	UpdatedAt time.Time `json:"updated_at"`
}

// NodeKind enumerates the kinds of nodes in the asset relationship graph.
type NodeKind string

const (
	NodeAsset         NodeKind = "asset"
	NodeService       NodeKind = "service"
	NodeWeakPassword  NodeKind = "weak_password"
	NodeVulnerability NodeKind = "vulnerability"
	NodeDomain        NodeKind = "domain"
)

// EdgeKind enumerates the relationship kinds in the graph.
type EdgeKind string

const (
	EdgeRuns             EdgeKind = "runs"
	EdgeHasWeakPassword  EdgeKind = "has_weak_password"
	EdgeHasVulnerability EdgeKind = "has_vulnerability"
	EdgeBelongsTo        EdgeKind = "belongs_to"
	EdgeDependsOn        EdgeKind = "depends_on"
)

// Node is a vertex in the relationship graph.
type Node struct {
	Kind NodeKind          `json:"kind"`
	ID   string            `json:"id"`
	Name string            `json:"name"`
	Meta map[string]string `json:"meta,omitempty"`
}

// Edge is a directed relationship between two nodes.
type Edge struct {
	From string   `json:"from"`
	To   string   `json:"to"`
	Kind EdgeKind `json:"kind"`
}

// Graph is the asset relationship graph. It is immutable once built;
// traversal is cycle-safe.
type Graph struct {
	Nodes map[string]*Node `json:"nodes"`
	Edges []Edge           `json:"edges"`

	adj map[string][]Edge `json:"-"`
	in  map[string][]Edge `json:"-"`
}

// Snapshot is an immutable, self-consistent version of the inventory and
// graph. Readers always observe a single committed snapshot.
type Snapshot struct {
	Version   int64             `json:"version"`
	Assets    map[string]*Asset `json:"assets"`
	Graph     *Graph            `json:"graph"`
	Conflicts []Conflict        `json:"conflicts"`
	WALOffset int64             `json:"wal_offset"`
	CreatedAt time.Time         `json:"created_at"`
	Stats     SnapshotStats     `json:"stats"`

	// Records is the full change stream the snapshot was built from. It makes
	// snapshots self-contained for recovery.
	Records []*RawRecord `json:"records,omitempty"`

	// identity maps identity keys ("hn:...", "ip:...") to asset ids.
	// Rebuilt on every snapshot; not persisted (derivable from Assets).
	identity map[string]string
}

// SnapshotStats summarizes a snapshot.
type SnapshotStats struct {
	AssetCount    int `json:"asset_count"`
	ServiceCount  int `json:"service_count"`
	NodeCount     int `json:"node_count"`
	EdgeCount     int `json:"edge_count"`
	ConflictCount int `json:"conflict_count"`
	SourceCount   int `json:"source_count"`
}
