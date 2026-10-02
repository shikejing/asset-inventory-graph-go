package inventory

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// identityIndex is a union-find structure over identity keys. Keys that
// appear together in a record belong to the same component; components are
// merged when a later record bridges them.
type identityIndex struct {
	keyComp  map[string]string
	compKeys map[string]map[string]bool
}

func newIdentityIndex() *identityIndex {
	return &identityIndex{
		keyComp:  map[string]string{},
		compKeys: map[string]map[string]bool{},
	}
}

// addRecord unions the components touched by keys and returns the
// deterministic component id that contains them.
func (idx *identityIndex) addRecord(keys []string) string {
	found := map[string]bool{}
	for _, k := range keys {
		if c, ok := idx.keyComp[k]; ok {
			found[c] = true
		}
	}
	var target string
	if len(found) > 0 {
		for c := range found {
			if target == "" || c < target {
				target = c
			}
		}
	} else {
		target = componentID(keys)
		idx.compKeys[target] = map[string]bool{}
	}
	for c := range found {
		if c == target {
			continue
		}
		for k := range idx.compKeys[c] {
			idx.compKeys[target][k] = true
			idx.keyComp[k] = target
		}
		delete(idx.compKeys, c)
	}
	for _, k := range keys {
		idx.compKeys[target][k] = true
		idx.keyComp[k] = target
	}
	return target
}

// finalIDs recomputes component ids from their final key sets, so the
// resulting asset ids depend only on the observed identity claims, not on
// the order in which records arrived.
func (idx *identityIndex) finalIDs() map[string]string {
	out := map[string]string{}
	for comp, keys := range idx.compKeys {
		ks := make([]string, 0, len(keys))
		for k := range keys {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		out[comp] = componentID(ks)
	}
	return out
}

// BuildSnapshot converges raw records into a single self-consistent snapshot.
// It is a pure function of the records and the configuration: replaying the
// same change stream always yields the same snapshot.
func BuildSnapshot(records []*RawRecord, cfg Config, version int64, walOffset int64) *Snapshot {
	recs := make([]*RawRecord, 0, len(records))
	for _, r := range records {
		recs = append(recs, normalizeRecord(r))
	}
	// Deterministic processing order: earliest observation wins for "first",
	// and ties are broken by source/record id regardless of arrival order.
	sort.Slice(recs, func(i, j int) bool {
		if !recs[i].Timestamp.Equal(recs[j].Timestamp) {
			return recs[i].Timestamp.Before(recs[j].Timestamp)
		}
		if recs[i].Source != recs[j].Source {
			return recs[i].Source < recs[j].Source
		}
		return recs[i].ID < recs[j].ID
	})

	idx := newIdentityIndex()
	recordComp := map[string]string{}
	for _, r := range recs {
		recordComp[r.ID] = idx.addRecord(r.identityKeys())
	}
	finalID := idx.finalIDs()

	// Group records by final component id.
	compRecords := map[string][]*RawRecord{}
	for _, r := range recs {
		c := finalID[recordComp[r.ID]]
		compRecords[c] = append(compRecords[c], r)
	}

	assets := map[string]*Asset{}
	var conflicts []Conflict
	for id, rs := range compRecords {
		asset, cs := mergeAsset(id, rs, cfg)
		assets[id] = asset
		conflicts = append(conflicts, cs...)
	}

	graph, keyToAsset := buildGraph(assets, idx, finalID)

	snap := &Snapshot{
		Version:   version,
		Assets:    assets,
		Graph:     graph,
		Conflicts: conflicts,
		WALOffset: walOffset,
		CreatedAt: time.Now().UTC(),
		Stats: SnapshotStats{
			AssetCount:    len(assets),
			NodeCount:     len(graph.Nodes),
			EdgeCount:     len(graph.Edges),
			ConflictCount: len(conflicts),
			SourceCount:   countSources(recs),
		},
	}
	snap.identity = keyToAsset
	snap.Stats.ServiceCount = countServices(assets)
	return snap
}

// mergeAsset merges the records of one component into a single asset.
func mergeAsset(id string, recs []*RawRecord, cfg Config) (*Asset, []Conflict) {
	a := &Asset{
		ID:       id,
		Attrs:    map[string]string{},
		Evidence: map[string][]ValueEvidence{},
	}
	ipSet := map[string]bool{}
	macSet := map[string]bool{}
	portSet := map[int]bool{}
	svcMap := map[string]*Service{}
	srcSet := map[SourceID]bool{}
	recIDs := map[string]bool{}
	depSet := map[string]bool{}

	addEvidence := func(attr, value string, r *RawRecord) {
		if value == "" {
			return
		}
		a.Evidence[attr] = append(a.Evidence[attr], ValueEvidence{
			Source: r.Source, Value: value, Timestamp: r.Timestamp, RecordID: r.ID,
		})
	}

	for _, r := range recs {
		srcSet[r.Source] = true
		recIDs[r.ID] = true
		if r.Timestamp.After(a.UpdatedAt) {
			a.UpdatedAt = r.Timestamp
		}
		addEvidence("hostname", r.Hostname, r)
		addEvidence("domain", r.Domain, r)
		addEvidence("os", r.OS, r)
		for _, ip := range r.IPs {
			ipSet[ip] = true
		}
		for _, m := range r.MACs {
			macSet[m] = true
		}
		for _, p := range r.Ports {
			portSet[p] = true
		}
		for k, v := range r.Attrs {
			addEvidence("attr."+k, v, r)
		}
		for _, s := range r.Services {
			key := fmt.Sprintf("%s|%d|%s", s.Name, s.Port, s.Protocol)
			svc := svcMap[key]
			if svc == nil {
				svc = &Service{Name: s.Name, Port: s.Port, Protocol: s.Protocol}
				svcMap[key] = svc
			}
			if s.Version != "" {
				svc.VersionEvidence = append(svc.VersionEvidence, ValueEvidence{
					Source: r.Source, Value: s.Version, Timestamp: r.Timestamp, RecordID: r.ID,
				})
			}
			svc.WeakPasswords = append(svc.WeakPasswords, s.WeakPasswords...)
			svc.Vulnerabilities = append(svc.Vulnerabilities, s.Vulnerabilities...)
			svc.Sources = append(svc.Sources, r.Source)
		}
		for _, dep := range r.DependsOn {
			depSet[dep] = true
		}
	}

	// Resolve single-valued attributes with the configured strategy.
	var conflicts []Conflict
	for _, attr := range []string{"hostname", "domain", "os"} {
		val, cs := resolve(attr, a.Evidence[attr], cfg)
		setAssetAttr(a, attr, val)
		conflicts = append(conflicts, cs...)
	}
	for attr, ev := range a.Evidence {
		if strings.HasPrefix(attr, "attr.") {
			val, cs := resolve(attr, ev, cfg)
			a.Attrs[strings.TrimPrefix(attr, "attr.")] = val
			conflicts = append(conflicts, cs...)
		}
	}

	a.IPs = sortedStrings(ipSet)
	a.MACs = sortedStrings(macSet)
	a.Ports = sortedInts(portSet)

	// Finalize services: merge version, dedupe multi-valued fields.
	svcKeys := make([]string, 0, len(svcMap))
	for k := range svcMap {
		svcKeys = append(svcKeys, k)
	}
	sort.Strings(svcKeys)
	for _, k := range svcKeys {
		svc := svcMap[k]
		if v, cs := resolve("version", svc.VersionEvidence, cfg); v != "" {
			svc.Version = v
			conflicts = append(conflicts, cs...)
		}
		svc.WeakPasswords = dedupeSorted(svc.WeakPasswords)
		svc.Vulnerabilities = dedupeSorted(svc.Vulnerabilities)
		svc.Sources = dedupeSources(svc.Sources)
		a.Services = append(a.Services, *svc)
	}

	a.Sources = dedupeSources(mapKeys(srcSet))
	a.RecordIDs = sortedStringSet(recIDs)
	a.depends = sortedStringSet(depSet)
	a.Conflicts = conflicts
	if a.Hostname == "" && len(a.IPs) > 0 {
		a.Hostname = a.IPs[0]
	}
	return a, conflicts
}

// resolve picks a winner among conflicting values according to the configured
// strategy and records a conflict when sources disagree.
func resolve(attr string, ev []ValueEvidence, cfg Config) (string, []Conflict) {
	if len(ev) == 0 {
		return "", nil
	}
	distinct := map[string]bool{}
	for _, e := range ev {
		distinct[e.Value] = true
	}
	if len(distinct) == 1 {
		return ev[0].Value, nil
	}

	strategy := cfg.strategyFor(attr)
	candidates := append([]ValueEvidence(nil), ev...)
	var reason string
	switch strategy {
	case StrategyLatest:
		sort.SliceStable(candidates, func(i, j int) bool {
			if !candidates[i].Timestamp.Equal(candidates[j].Timestamp) {
				return candidates[i].Timestamp.After(candidates[j].Timestamp)
			}
			pi, pj := cfg.priorityOf(candidates[i].Source), cfg.priorityOf(candidates[j].Source)
			if pi != pj {
				return pi > pj
			}
			return candidates[i].Source < candidates[j].Source
		})
		reason = fmt.Sprintf("latest: observed at %s, newer than %s",
			candidates[0].Timestamp.Format(time.RFC3339), candidates[1].Timestamp.Format(time.RFC3339))
	case StrategyFirst:
		sort.SliceStable(candidates, func(i, j int) bool {
			if !candidates[i].Timestamp.Equal(candidates[j].Timestamp) {
				return candidates[i].Timestamp.Before(candidates[j].Timestamp)
			}
			if candidates[i].Source != candidates[j].Source {
				return candidates[i].Source < candidates[j].Source
			}
			return candidates[i].RecordID < candidates[j].RecordID
		})
		reason = fmt.Sprintf("first: earliest observation at %s",
			candidates[0].Timestamp.Format(time.RFC3339))
	default: // StrategyPriority
		sort.SliceStable(candidates, func(i, j int) bool {
			pi, pj := cfg.priorityOf(candidates[i].Source), cfg.priorityOf(candidates[j].Source)
			if pi != pj {
				return pi > pj
			}
			if !candidates[i].Timestamp.Equal(candidates[j].Timestamp) {
				return candidates[i].Timestamp.After(candidates[j].Timestamp)
			}
			return candidates[i].Source < candidates[j].Source
		})
		reason = fmt.Sprintf("priority: source %s (p=%d) outranks %s (p=%d)",
			candidates[0].Source, cfg.priorityOf(candidates[0].Source),
			candidates[1].Source, cfg.priorityOf(candidates[1].Source))
	}

	return candidates[0].Value, []Conflict{{
		Attr:       attr,
		Chosen:     candidates[0].Value,
		ChosenSrc:  candidates[0].Source,
		Reason:     reason,
		Candidates: candidates,
	}}
}

func setAssetAttr(a *Asset, attr, val string) {
	switch attr {
	case "hostname":
		a.Hostname = val
	case "domain":
		a.Domain = val
	case "os":
		a.OS = val
	}
}

// ---- helpers ----

func sortedStringSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func sortedStrings(set map[string]bool) []string { return sortedStringSet(set) }

func sortedInts(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

func mapKeys(set map[SourceID]bool) []SourceID {
	out := make([]SourceID, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	return out
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	sort.Strings(in)
	out := in[:1]
	for _, v := range in[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

func dedupeSources(in []SourceID) []SourceID {
	set := map[SourceID]bool{}
	for _, s := range in {
		set[s] = true
	}
	out := make([]SourceID, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func countSources(recs []*RawRecord) int {
	set := map[SourceID]bool{}
	for _, r := range recs {
		set[r.Source] = true
	}
	return len(set)
}

func countServices(assets map[string]*Asset) int {
	n := 0
	for _, a := range assets {
		n += len(a.Services)
	}
	return n
}
