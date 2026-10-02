package store

import "sync"

// MemoryStore 是进程内持久化实现，语义与 FileStore 一致（原子批量替换），
// 用于本地内存管道演示与测试；重启恢复场景使用 FileStore。
type MemoryStore struct {
	mu      sync.Mutex
	records []ObservationRecord
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

func (s *MemoryStore) Load() ([]ObservationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ObservationRecord, len(s.records))
	copy(out, s.records)
	return out, nil
}

func (s *MemoryStore) Append(recs []ObservationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, recs...)
	return nil
}

func (s *MemoryStore) ReplaceAll(recs []ObservationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ObservationRecord, len(recs))
	copy(out, recs)
	s.records = out
	return nil
}

func (s *MemoryStore) Close() error { return nil }
