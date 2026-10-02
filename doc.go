// Package inventory implements an internal-network asset inventory engine.
//
// Multiple scanning sources produce raw asset records (RawRecord) that
// overlap, duplicate and contradict each other. The engine converges them
// into a single unique asset inventory (BuildSnapshot) and maintains an
// asset relationship graph (runs / has_weak_password / has_vulnerability /
// belongs_to / depends_on).
//
// Key properties:
//
//   - Dedup is based on stable identity claims (normalized hostnames, IPs,
//     MACs) via a union-find over identity keys; asset ids are derived from
//     the identity key set, so convergence is independent of arrival order.
//   - Attribute conflicts are resolved by configurable per-attribute merge
//     rules (priority / latest / first / union) and every conflict retains
//     all contributing evidence.
//   - Incremental ingestion is idempotent (record-id dedup), full rebuilds
//     coexist with incremental refresh without losing changes, and queries
//     always read an immutable committed snapshot (lock-free).
//   - Persistence uses a checksum-framed write-ahead log plus atomically
//     renamed snapshots; torn writes from crashes are detected and discarded
//     on recovery.
package inventory
