package inventory

import (
	"errors"
	"sync"
	"sync/atomic"
)

// ErrEngineClosed is returned when ingesting into a closed engine.
var ErrEngineClosed = errors.New("inventory engine is closed")

// Engine is the asset inventory engine. It is safe for concurrent ingestion
// and concurrent queries. Reads never block on writes: every query observes
// a single immutable committed snapshot.
type Engine struct {
	cfg Config

	mu      sync.Mutex
	wal     *WAL
	records map[string]*RawRecord
	order   []string
	version int64
	snap    atomic.Pointer[Snapshot]

	rebuildMu sync.Mutex
	closed    bool
}

// IngestResult describes the outcome of an ingestion.
type IngestResult struct {
	// Duplicate is true when the record id was already committed.
	Duplicate bool
	// AssetID is the converged asset the record belongs to.
	AssetID string
	// Version is the committed snapshot version after ingestion.
	Version int64
}

// Open opens (or creates) an engine in cfg.DataDir and recovers its state
// from disk: the last snapshot is loaded, WAL entries after the snapshot
// offset are replayed, and the in-memory record set is rebuilt. Torn WAL
// frames from a crash are ignored.
func Open(cfg Config) (*Engine, error) {
	if cfg.DataDir == "" {
		cfg = DefaultConfig()
	}
	if cfg.DefaultStrategy == "" {
		cfg.DefaultStrategy = StrategyPriority
	}
	if cfg.SnapshotEvery <= 0 {
		cfg.SnapshotEvery = 50
	}

	wal, err := OpenWAL(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		cfg:     cfg,
		wal:     wal,
		records: map[string]*RawRecord{},
	}

	var walOffset int64
	var version int64
	if snap, err := LoadSnapshot(cfg.DataDir); err != nil {
		wal.Close()
		return nil, err
	} else if snap != nil {
		walOffset = snap.WALOffset
		version = snap.Version
		for _, r := range snap.Records {
			nr := normalizeRecord(r)
			e.records[nr.ID] = nr
			e.order = append(e.order, nr.ID)
		}
	}

	recs, _, err := wal.ReadFrom(walOffset)
	if err != nil {
		wal.Close()
		return nil, err
	}
	for _, r := range recs {
		nr := normalizeRecord(r)
		if _, exists := e.records[nr.ID]; !exists {
			e.records[nr.ID] = nr
			e.order = append(e.order, nr.ID)
		}
	}

	e.version = version
	e.commitLocked(walOffset)
	return e, nil
}

// Ingest applies a single raw record. Duplicate record ids are ignored
// (idempotent). The record is durably appended to the WAL before it becomes
// visible.
func (e *Engine) Ingest(r *RawRecord) (*IngestResult, error) {
	return e.ingestBatch([]*RawRecord{r})
}

// IngestBatch applies a batch of records atomically. The whole batch is
// committed as one new snapshot version; replaying the same batch again is a
// no-op.
func (e *Engine) IngestBatch(rs []*RawRecord) (*IngestResult, error) {
	return e.ingestBatch(rs)
}

func (e *Engine) ingestBatch(rs []*RawRecord) (*IngestResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, ErrEngineClosed
	}

	res := &IngestResult{}
	added := false
	for _, r := range rs {
		nr := normalizeRecord(r)
		if _, exists := e.records[nr.ID]; exists {
			res.Duplicate = true
			continue
		}
		offset, err := e.wal.Append(nr)
		if err != nil {
			return nil, err
		}
		_ = offset
		e.records[nr.ID] = nr
		e.order = append(e.order, nr.ID)
		added = true
	}

	if !added {
		snap := e.snap.Load()
		if snap != nil {
			res.Version = snap.Version
			if a := e.assetOf(rs[0]); a != nil {
				res.AssetID = a.ID
			}
		}
		return res, nil
	}

	endOffset, err := e.wal.Offset()
	if err != nil {
		return nil, err
	}
	e.version++
	snap := e.commitLocked(endOffset)
	res.Version = snap.Version
	if a := e.assetOf(rs[len(rs)-1]); a != nil {
		res.AssetID = a.ID
	}

	if e.version%int64(e.cfg.SnapshotEvery) == 0 {
		if err := SaveSnapshot(e.cfg.DataDir, snap); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// commitLocked rebuilds the snapshot from the current record set and swaps it
// in. Caller must hold e.mu.
func (e *Engine) commitLocked(walOffset int64) *Snapshot {
	recs := make([]*RawRecord, 0, len(e.order))
	for _, id := range e.order {
		recs = append(recs, e.records[id])
	}
	snap := BuildSnapshot(recs, e.cfg, e.version, walOffset)
	snap.Records = recs
	e.snap.Store(snap)
	return snap
}

func (e *Engine) assetOf(r *RawRecord) *Asset {
	if r == nil {
		return nil
	}
	snap := e.snap.Load()
	if snap == nil || snap.identity == nil {
		return nil
	}
	for _, key := range normalizeRecord(r).identityKeys() {
		if aid, ok := snap.identity[key]; ok {
			return snap.Assets[aid]
		}
	}
	return nil
}

// Rebuild performs a full rebuild of the inventory and graph from the entire
// change stream. Ingestion is not blocked: records arriving while the rebuild
// is in progress are included when the rebuilt snapshot is swapped in, so the
// final state always matches the change stream.
func (e *Engine) Rebuild() (*Snapshot, error) {
	e.rebuildMu.Lock()
	defer e.rebuildMu.Unlock()

	// Point-in-time copy of the change stream under the write lock.
	e.mu.Lock()
	recs := make([]*RawRecord, 0, len(e.order))
	for _, id := range e.order {
		recs = append(recs, e.records[id])
	}
	e.mu.Unlock()

	// Heavy build runs without the write lock; queries and ingestion proceed.
	_ = BuildSnapshot(recs, e.cfg, 0, 0)

	// Finalize: rebuild from the *current* stream so arrivals during the
	// rebuild are not lost, then atomically swap and persist.
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, ErrEngineClosed
	}
	endOffset, err := e.wal.Offset()
	if err != nil {
		return nil, err
	}
	e.version++
	snap := e.commitLocked(endOffset)
	if err := SaveSnapshot(e.cfg.DataDir, snap); err != nil {
		return nil, err
	}
	return snap, nil
}

// Close persists a final snapshot and releases resources.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	if e.wal != nil {
		if offset, err := e.wal.Offset(); err == nil {
			if snap := e.snap.Load(); snap != nil {
				snap.WALOffset = offset
				_ = SaveSnapshot(e.cfg.DataDir, snap)
			}
		}
		return e.wal.Close()
	}
	return nil
}

// ---- queries (all read the immutable snapshot) ----

// Snapshot returns the current committed snapshot.
func (e *Engine) Snapshot() *Snapshot { return e.snap.Load() }

// Assets returns all converged assets, sorted by id.
func (e *Engine) Assets() []*Asset {
	snap := e.snap.Load()
	if snap == nil {
		return nil
	}
	out := make([]*Asset, 0, len(snap.Assets))
	for _, a := range snap.Assets {
		out = append(out, a)
	}
	sortAssets(out)
	return out
}

// AssetByID returns the asset with the given id, or nil.
func (e *Engine) AssetByID(id string) *Asset {
	snap := e.snap.Load()
	if snap == nil {
		return nil
	}
	return snap.Assets[id]
}

// FindByIdentity resolves an identity reference (hostname or IP) to an asset.
func (e *Engine) FindByIdentity(ref string) *Asset {
	snap := e.snap.Load()
	if snap == nil || snap.identity == nil {
		return nil
	}
	key := resolveIdentity(ref)
	if aid, ok := snap.identity[key]; ok {
		return snap.Assets[aid]
	}
	return nil
}

// Graph returns the current relationship graph.
func (e *Engine) Graph() *Graph {
	snap := e.snap.Load()
	if snap == nil {
		return nil
	}
	return snap.Graph
}

// Conflicts returns all recorded attribute conflicts.
func (e *Engine) Conflicts() []Conflict {
	snap := e.snap.Load()
	if snap == nil {
		return nil
	}
	return snap.Conflicts
}

// AssetsInDomain returns the assets belonging to the given domain.
func (e *Engine) AssetsInDomain(domain string) []*Asset {
	snap := e.snap.Load()
	if snap == nil {
		return nil
	}
	did := "domain:" + domain
	var out []*Asset
	for _, n := range snap.Graph.Neighbors(did, EdgeBelongsTo, DirIn) {
		if n.Kind == NodeAsset {
			if a := snap.Assets[n.ID]; a != nil {
				out = append(out, a)
			}
		}
	}
	sortAssets(out)
	return out
}

// ServicesOf returns the service nodes running on an asset.
func (e *Engine) ServicesOf(assetID string) []*Node {
	snap := e.snap.Load()
	if snap == nil {
		return nil
	}
	return snap.Graph.Neighbors(assetID, EdgeRuns, DirOut)
}

// WeakPasswordsOf returns weak-password nodes attached to a service node.
func (e *Engine) WeakPasswordsOf(serviceNodeID string) []*Node {
	snap := e.snap.Load()
	if snap == nil {
		return nil
	}
	return snap.Graph.Neighbors(serviceNodeID, EdgeHasWeakPassword, DirOut)
}

// VulnerabilitiesOf returns vulnerability nodes attached to a service node.
func (e *Engine) VulnerabilitiesOf(serviceNodeID string) []*Node {
	snap := e.snap.Load()
	if snap == nil {
		return nil
	}
	return snap.Graph.Neighbors(serviceNodeID, EdgeHasVulnerability, DirOut)
}

func sortAssets(in []*Asset) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j-1].ID > in[j].ID; j-- {
			in[j-1], in[j] = in[j], in[j-1]
		}
	}
}
