package index

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Store persists index snapshots. Implementations must make Save atomic from
// the point of view of Load: a crash/interruption during Save must leave the
// previous complete snapshot readable.
type Store interface {
	Load() (*Snapshot, error)
	Save(snap *Snapshot) error
}

// FileStore persists the snapshot as JSON at path, writing via a sibling
// temporary file and renaming it into place. Because rename is atomic on a
// single filesystem, observers either see the previous file or the complete
// new file, never a partially written one.
type FileStore struct {
	path string
}

// NewFileStore creates a FileStore for path.
func NewFileStore(path string) *FileStore { return &FileStore{path: path} }

// Load reads and decodes the snapshot. A missing file yields an empty
// snapshot. Leftover temporary files from an interrupted Save (matching
// "<basename>.tmp-*") are never consulted and are best-effort removed, so
// recovery always starts from the last complete snapshot and leaves no
// half-finished artifacts behind.
func (s *FileStore) Load() (*Snapshot, error) {
	s.sweepTemps()
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return &Snapshot{Records: map[string]*Record{}}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	snap, err := decodeSnapshot(f)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStoreCorrupt, err)
	}
	return snap, nil
}

// sweepTemps best-effort removes temp files left by an interrupted Save.
func (s *FileStore) sweepTemps() {
	dir, base := filepath.Dir(s.path), filepath.Base(s.path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := base + ".tmp-"
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if name := e.Name(); len(name) > len(prefix) && name[:len(prefix)] == prefix {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

// Save encodes the snapshot to a temp file, fsyncs it and renames it over
// the destination so readers can only ever see a complete old or new file.
// If this process is interrupted at any point before the rename, the old
// snapshot (if any) is untouched.
func (s *FileStore) Save(snap *Snapshot) (err error) {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmpName) // best effort: no half-finished artifact
		}
	}()
	if err = encodeSnapshot(tmp, snap); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

// encodeSnapshot / decodeSnapshot are separated for testability.
func encodeSnapshot(w io.Writer, snap *Snapshot) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(snap)
}

func decodeSnapshot(r io.Reader) (*Snapshot, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(bytes.TrimSpace(data), &snap); err != nil {
		return nil, err
	}
	if snap.Records == nil {
		snap.Records = map[string]*Record{}
	}
	// Integrity check: stored records must match their map key.
	for k, rec := range snap.Records {
		if rec == nil {
			return nil, fmt.Errorf("nil record for key %q", k)
		}
		if rec.Key() != k {
			return nil, fmt.Errorf("record key mismatch: map=%q record=%q", k, rec.Key())
		}
	}
	return &snap, nil
}
