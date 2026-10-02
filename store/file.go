package store

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// FileStore 基于只增日志（每行一帧 + SHA256 校验）实现崩溃安全持久化。
//   - 每条已提交记录一帧，追加后 fsync，进程重启可完整还原。
//   - 崩溃导致的半行/坏帧在 Load 时被识别并截断，不会残留“写了一半”的记录。
//   - ReplaceAll（全量重建落盘）走 temp + fsync + rename + 目录 fsync，原子替换。
type FileStore struct {
	path string
	f    *os.File
	w    *bufio.Writer
}

// frame 是磁盘上的单帧：p 为 ObservationRecord 的 JSON，c 为其校验和。
type frame struct {
	C string `json:"c"`
	P string `json:"p"`
}

func checksum(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// NewFileStore 打开（必要时创建）日志文件。
func NewFileStore(path string) (*FileStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &FileStore{path: path, f: f, w: bufio.NewWriter(f)}, nil
}

// Load 读取并校验全部完整帧；尾部残缺帧会被原子截断丢弃。
func (s *FileStore) Load() ([]ObservationRecord, error) {
	if err := s.w.Flush(); err != nil {
		return nil, err
	}
	if _, err := s.f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(s.f)
	scanner.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	var recs []ObservationRecord
	validBytes := int64(0)
	var pos int64
	torn := false
	for scanner.Scan() {
		line := scanner.Bytes()
		pos += int64(len(line)) + 1 // \n
		var fr frame
		if err := json.Unmarshal(line, &fr); err != nil || checksum(fr.P) != fr.C {
			torn = true
			break
		}
		var rec ObservationRecord
		if err := json.Unmarshal([]byte(fr.P), &rec); err != nil {
			torn = true
			break
		}
		recs = append(recs, rec)
		validBytes = pos
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	// Seek 回末尾，保证后续追加位置正确。
	if _, err := s.f.Seek(0, io.SeekEnd); err != nil {
		return nil, err
	}
	if torn {
		// 丢弃残缺尾帧，保证日志中不存在半写记录。
		if err := s.f.Truncate(validBytes); err != nil {
			return nil, err
		}
		if _, err := s.f.Seek(0, io.SeekEnd); err != nil {
			return nil, err
		}
	}
	return recs, nil
}

// Append 顺序追加并 fsync；每帧自带校验和，崩溃只可能丢最后一帧的残缺部分。
func (s *FileStore) Append(recs []ObservationRecord) error {
	if len(recs) == 0 {
		return nil
	}
	buf := bufio.NewWriter(s.f)
	for _, rec := range recs {
		p, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		fr := frame{C: checksum(string(p)), P: string(p)}
		b, err := json.Marshal(fr)
		if err != nil {
			return err
		}
		if _, err := buf.Write(b); err != nil {
			return err
		}
		if err := buf.WriteByte('\n'); err != nil {
			return err
		}
	}
	if err := buf.Flush(); err != nil {
		return err
	}
	return s.f.Sync()
}

// ReplaceAll 原子替换全部记录（全量重建落盘）。
func (s *FileStore) ReplaceAll(recs []ObservationRecord) error {
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".log-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }
	w := bufio.NewWriter(tmp)
	for _, rec := range recs {
		p, err := json.Marshal(rec)
		if err != nil {
			cleanup()
			return err
		}
		fr := frame{C: checksum(string(p)), P: string(p)}
		b, err := json.Marshal(fr)
		if err != nil {
			cleanup()
			return err
		}
		if _, err := w.Write(b); err != nil {
			cleanup()
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			cleanup()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil { // 文件内容落盘
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	// 重新打开追加句柄。
	f, err := os.OpenFile(s.path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	_ = s.f.Close()
	s.f = f
	s.w = bufio.NewWriter(f)
	return nil
}

// Close 刷新并关闭。
func (s *FileStore) Close() error {
	if s == nil || s.f == nil {
		return nil
	}
	if err := s.w.Flush(); err != nil {
		return err
	}
	if err := s.f.Sync(); err != nil {
		return err
	}
	return s.f.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer d.Close()
	return d.Sync()
}
