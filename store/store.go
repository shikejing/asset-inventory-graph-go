package store

import "github.com/shikejing/asset-inventory-graph-go/model"

// ObservationRecord 是持久化用的幂等观察记录。
type ObservationRecord struct {
	DedupKey string
	Record   model.RawRecord
}

// Store 定义持久化接口（原子提交、崩溃恢复）。
type Store interface {
	Load() (records []ObservationRecord, err error)
	Append(recs []ObservationRecord) error
	ReplaceAll(recs []ObservationRecord) error
	Close() error
}
