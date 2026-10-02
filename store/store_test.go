package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shikejing/asset-inventory-graph-go/model"
)

func tmpDB(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "sub", "inventory.log")
}

func rec(k string) ObservationRecord {
	return ObservationRecord{
		DedupKey: k,
		Record:   model.RawRecord{Source: "s", Hostnames: []string{k}},
	}
}

func TestAppendLoadRoundtrip(t *testing.T) {
	path := tmpDB(t)
	s, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append([]ObservationRecord{rec("a"), rec("b")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].DedupKey != "a" || got[1].DedupKey != "b" {
		t.Fatalf("reload: %+v", got)
	}
	_ = s2.Close()
}

func TestTornTailTruncated(t *testing.T) {
	path := tmpDB(t)
	s, _ := NewFileStore(path)
	_ = s.Append([]ObservationRecord{rec("a"), rec("b")})
	_ = s.Close()

	// 模拟崩溃：在文件尾部写入半帧（无换行/校验错误），半成品不得残留为记录。
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{\"c\":\"deadbeef\",\"p\":\"half-written-no-newline"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	s2, _ := NewFileStore(path)
	got, err := s2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("torn tail must be dropped, got %d", len(got))
	}
	// 截断后继续追加，日志仍然可用（没有半写记录挡路）。
	if err := s2.Append([]ObservationRecord{rec("c")}); err != nil {
		t.Fatal(err)
	}
	got, _ = s2.Load()
	if len(got) != 3 || got[2].DedupKey != "c" {
		t.Fatalf("append after truncate: %+v", got)
	}
	_ = s2.Close()
}

func TestReplaceAllAtomic(t *testing.T) {
	path := tmpDB(t)
	s, _ := NewFileStore(path)
	_ = s.Append([]ObservationRecord{rec("a"), rec("b"), rec("c")})
	if err := s.ReplaceAll([]ObservationRecord{rec("x"), rec("y")}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Load()
	if len(got) != 2 || got[0].DedupKey != "x" {
		t.Fatalf("replace: %+v", got)
	}
	// 替换后仍可继续追加
	if err := s.Append([]ObservationRecord{rec("z")}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Load()
	if len(got) != 3 || got[2].DedupKey != "z" {
		t.Fatalf("append after replace: %+v", got)
	}
	_ = s.Close()
}

func TestMemoryStore(t *testing.T) {
	m := NewMemoryStore()
	_ = m.Append([]ObservationRecord{rec("a")})
	_ = m.ReplaceAll([]ObservationRecord{rec("b")})
	got, _ := m.Load()
	if len(got) != 1 || got[0].DedupKey != "b" {
		t.Fatalf("memstore: %+v", got)
	}
}
