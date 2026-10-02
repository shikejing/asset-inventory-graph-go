package inventory

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
)

// WAL is an append-only write-ahead log of raw records. Each record is
// framed with a length and a CRC32 checksum: a torn write (crash mid-append)
// is detected on replay and ignored, so no half-written record ever poisons
// the inventory.
type WAL struct {
	f    *os.File
	path string
}

const walMagic = "INV1"

// OpenWAL opens (or creates) the WAL in dir. A torn tail left by a crash is
// truncated away.
func OpenWAL(dir string) (*WAL, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "wal.log")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	w := &WAL{f: f, path: path}
	if err := w.truncateTornTail(); err != nil {
		f.Close()
		return nil, err
	}
	return w, nil
}

// Append durably appends a record and returns its byte offset in the log.
func (w *WAL) Append(r *RawRecord) (int64, error) {
	payload, err := json.Marshal(r)
	if err != nil {
		return 0, err
	}
	frame := make([]byte, 4+4+len(payload)+4)
	copy(frame[0:4], walMagic)
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(payload)))
	copy(frame[8:8+len(payload)], payload)
	crc := crc32.ChecksumIEEE(payload)
	binary.BigEndian.PutUint32(frame[8+len(payload):], crc)

	offset, err := w.f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}
	if _, err := w.f.Write(frame); err != nil {
		return 0, err
	}
	if err := w.f.Sync(); err != nil {
		return 0, err
	}
	return offset, nil
}

// ReadFrom replays all valid records starting at offset. It returns the
// records and the byte offset of the first invalid/torn frame (or the end
// of the file).
func (w *WAL) ReadFrom(offset int64) ([]*RawRecord, int64, error) {
	if _, err := w.f.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, err
	}
	var recs []*RawRecord
	pos := offset
	for {
		header := make([]byte, 8)
		if _, err := io.ReadFull(w.f, header); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break // clean end of log or torn header
			}
			return recs, pos, err
		}
		if string(header[0:4]) != walMagic {
			break // torn frame
		}
		n := binary.BigEndian.Uint32(header[4:8])
		if n > 16*1024*1024 {
			break // implausible length: treat as torn
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(w.f, payload); err != nil {
			break // torn payload
		}
		crcBuf := make([]byte, 4)
		if _, err := io.ReadFull(w.f, crcBuf); err != nil {
			break // torn checksum
		}
		if binary.BigEndian.Uint32(crcBuf) != crc32.ChecksumIEEE(payload) {
			break // corrupt payload
		}
		var r RawRecord
		if err := json.Unmarshal(payload, &r); err != nil {
			break
		}
		pos += int64(8 + 4 + n)
		recs = append(recs, &r)
	}
	return recs, pos, nil
}

// truncateTornTail removes a partial frame left by a crash.
func (w *WAL) truncateTornTail() error {
	_, end, err := w.ReadFrom(0)
	if err != nil {
		return err
	}
	info, err := w.f.Stat()
	if err != nil {
		return err
	}
	if end < info.Size() {
		if err := w.f.Truncate(end); err != nil {
			return err
		}
	}
	_, err = w.f.Seek(end, io.SeekStart)
	return err
}

// Offset returns the current end-of-log offset.
func (w *WAL) Offset() (int64, error) {
	return w.f.Seek(0, io.SeekEnd)
}

// Close closes the WAL file.
func (w *WAL) Close() error {
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// ---- snapshot persistence ----

// SaveSnapshot atomically writes a snapshot: write to a temp file, fsync,
// rename over the real file, fsync the directory. A crash at any point
// leaves either the old or the new complete file, never a half-written one.
func SaveSnapshot(dir string, snap *Snapshot) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "snapshot.json.tmp")
	final := filepath.Join(dir, "snapshot.json")
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(payload); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	return syncDir(dir)
}

// LoadSnapshot reads the last committed snapshot. A missing or corrupt
// snapshot is reported as (nil, nil) so the caller can rebuild from the WAL.
func LoadSnapshot(dir string) (*Snapshot, error) {
	final := filepath.Join(dir, "snapshot.json")
	data, err := os.ReadFile(final)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, nil // corrupt snapshot: fall back to WAL replay
	}
	if snap.Assets == nil || snap.Graph == nil {
		return nil, nil
	}
	return &snap, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
