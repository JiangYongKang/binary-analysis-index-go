// Package index stores analysis results for local binary samples.
//
// Guarantees:
//
//   - Incremental: a (content hash, rule version) pair that already has a
//     record (success or classified failure) is never analysed twice.
//   - Concurrent de-duplication: concurrent requests for the same target
//     share one in-flight analysis and observe identical results.
//   - Version coexistence: results produced under different rule-set
//     versions are kept side by side and remain reproducible.
//   - Snapshot consistency: readers observe either the complete old state or
//     the complete new state, never a half-applied update; persistence uses
//     temp-file + rename, so an interrupted update leaves the previous
//     snapshot intact and no half-finished records.
package index

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/highcumontoa/binary-analysis-index-go/internal/analysis"
)

// Status is the lifecycle state of a record.
type Status string

const (
	StatusSuccess Status = "success"
	StatusFailed  Status = "failed"
)

// ErrorRecord mirrors analysis.Failure for persistence.
type ErrorRecord struct {
	Kind    string `json:"kind"`
	File    string `json:"file"`
	Offset  int64  `json:"offset"`
	RuleID  string `json:"rule_id,omitempty"`
	Message string `json:"message"`
}

// MatchRecord mirrors analysis.Match for persistence.
type MatchRecord struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// Record is one stored analysis outcome, keyed by sample and rule version.
type Record struct {
	SampleID string        `json:"sample_id"`
	Filename string        `json:"filename"`
	Size     int64         `json:"size"`
	Version  string        `json:"rule_version"`
	Status   Status        `json:"status"`
	Format   string        `json:"format,omitempty"`
	Class    string        `json:"class,omitempty"`
	Machine  string        `json:"machine,omitempty"`
	Verdict  string        `json:"verdict,omitempty"`
	Matches  []MatchRecord `json:"matches,omitempty"`
	Basis    string        `json:"basis,omitempty"`
	Error    *ErrorRecord  `json:"error,omitempty"`
}

// Key returns the identity of a record within the index.
func (r *Record) Key() string { return RecordKey(r.SampleID, r.Version) }

// RecordKey is the (content, rule version) composite key.
func RecordKey(sampleID, ruleVersion string) string {
	return sampleID + "\x00" + ruleVersion
}

// Snapshot is one immutable generation of the index.
type Snapshot struct {
	Generation int                `json:"generation"`
	Records    map[string]*Record `json:"records"`
}

// Clone returns a deep copy of the snapshot.
func (s *Snapshot) Clone() *Snapshot {
	cp := &Snapshot{Generation: s.Generation, Records: make(map[string]*Record, len(s.Records))}
	for k, r := range s.Records {
		rc := *r
		if r.Matches != nil {
			rc.Matches = append([]MatchRecord(nil), r.Matches...)
		}
		if r.Error != nil {
			e := *r.Error
			rc.Error = &e
		}
		cp.Records[k] = &rc
	}
	return cp
}

// AnalyzerFunc abstracts the analysis backend so the index does not depend on
// a concrete type (tests inject counting/failing analyzers). The sampleID is
// provided so implementations need not re-hash content.
type AnalyzerFunc func(ctx context.Context, file string, sampleID string, ruleVersion string) (*analysis.Result, error)

// Option configures an Index.
type Option func(*Index)

// WithStore sets the persistence store (nil keeps the index in-memory only).
func WithStore(s Store) Option { return func(i *Index) { i.store = s } }

// Index coordinates caching, single-flight analysis and snapshots.
type Index struct {
	analyzer AnalyzerFunc
	store    Store

	mu      sync.Mutex
	state   *Snapshot          // always a complete, immutable snapshot
	flights map[string]*flight // keyed by RecordKey
}

// flight represents one shared in-progress analysis.
type flight struct {
	done   chan struct{}
	result *Record
	err    error
}

// New creates an index. Existing state is loaded from the store, if any.
// A nil analyzer produces a read-only index (Scan will fail); this is useful
// for tools that only query a persisted snapshot.
func New(analyzer AnalyzerFunc, opts ...Option) (*Index, error) {
	i := &Index{
		analyzer: analyzer,
		state:    &Snapshot{Records: map[string]*Record{}},
		flights:  map[string]*flight{},
	}
	for _, o := range opts {
		o(i)
	}
	if i.store != nil {
		snap, err := i.store.Load()
		if err != nil {
			return nil, err
		}
		if snap.Records == nil {
			snap.Records = map[string]*Record{}
		}
		i.state = snap
	}
	return i, nil
}

// Scan ensures a sample is analysed under ruleVersion and returns the
// resulting record. The sampleID is the content hash.
//
// Concurrent Scans for the same (sampleID, ruleVersion) share one analysis
// and receive identical results. A caller whose context is cancelled or
// times out while waiting abandons only its own wait: the shared analysis
// keeps running, its result is still committed, and neither the index nor
// other waiters are affected.
func (i *Index) Scan(ctx context.Context, file, sampleID string, ruleVersion string) (*Record, error) {
	key := RecordKey(sampleID, ruleVersion)

	i.mu.Lock()
	if rec, ok := i.state.Records[key]; ok {
		i.mu.Unlock()
		return rec, nil // incremental: never re-analyse known content
	}
	if f, ok := i.flights[key]; ok {
		i.mu.Unlock()
		return i.await(ctx, f) // join the in-flight analysis
	}
	f := &flight{done: make(chan struct{})}
	i.flights[key] = f
	i.mu.Unlock()

	if i.analyzer == nil {
		i.mu.Lock()
		delete(i.flights, key)
		f.err = errors.New("index opened read-only: no analyzer configured")
		i.mu.Unlock()
		close(f.done) // release any waiters that already joined
		return nil, f.err
	}

	// Run detached from any single caller's lifecycle: cancellation of one
	// request must not cancel work shared by other concurrent requests.
	go i.runAndCommit(key, file, sampleID, ruleVersion, f)

	return i.await(ctx, f)
}

// await waits for the shared flight, or returns when the caller gives up.
func (i *Index) await(ctx context.Context, f *flight) (*Record, error) {
	select {
	case <-f.done:
		return f.result, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// runAndCommit performs the analysis once and publishes its outcome.
func (i *Index) runAndCommit(key, file, sampleID, ruleVersion string, f *flight) {
	defer close(f.done)

	result, err := i.analyzer(context.Background(), file, sampleID, ruleVersion)
	if err != nil {
		// Infrastructure failure: nothing is cached and waiters may retry.
		i.mu.Lock()
		delete(i.flights, key)
		f.err = err
		i.mu.Unlock()
		return
	}

	rec := toRecord(sampleID, result)
	i.mu.Lock()
	defer i.mu.Unlock()
	// Persist BEFORE publishing: on persistence failure we keep the old
	// complete state and surface the error rather than exposing new state
	// that was not durably recorded. Nothing partial is ever visible.
	if i.store != nil {
		next := i.state.Clone()
		next.Records[key] = rec
		next.Generation++
		if err := i.store.Save(next); err != nil {
			delete(i.flights, key)
			f.err = fmt.Errorf("persist index: %w", err)
			return
		}
		i.state = next // publish the already-persisted snapshot
	} else {
		next := i.state.Clone()
		next.Records[key] = rec
		next.Generation++
		i.state = next
	}
	f.result = rec
	delete(i.flights, key)
}

// Lookup returns the stored record for a sample under a rule version.
func (i *Index) Lookup(sampleID, ruleVersion string) (*Record, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	rec, ok := i.state.Records[RecordKey(sampleID, ruleVersion)]
	return rec, ok
}

// LookupAnyVersion returns records for all rule versions of a sample.
func (i *Index) LookupAnyVersion(sampleID string) []*Record {
	i.mu.Lock()
	defer i.mu.Unlock()
	var out []*Record
	for _, r := range i.state.Records {
		if r.SampleID == sampleID {
			out = append(out, r)
		}
	}
	return out
}

// Current returns an immutable snapshot of the complete index state. The
// returned snapshot is a private deep copy: callers may read it freely
// while writers publish newer generations.
func (i *Index) Current() *Snapshot {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.state.Clone()
}

// Count returns the number of stored records.
func (i *Index) Count() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.state.Records)
}

// toRecord converts an analysis result into an index record.
func toRecord(sampleID string, r *analysis.Result) *Record {
	rec := &Record{
		SampleID: sampleID,
		Filename: r.Filename,
		Size:     r.Size,
		Version:  r.Version,
		Format:   r.Format,
		Class:    r.Class,
		Machine:  r.Machine,
		Verdict:  string(r.Verdict),
		Basis:    r.Basis,
	}
	for _, m := range r.Matches {
		rec.Matches = append(rec.Matches, MatchRecord{RuleID: m.RuleID, Severity: m.Severity, Message: m.Message})
	}
	if r.IsFailure() {
		rec.Status = StatusFailed
		rec.Verdict = ""
		rec.Error = &ErrorRecord{
			Kind:    string(r.Failed.Kind),
			File:    r.Failed.File,
			Offset:  r.Failed.Offset,
			RuleID:  r.Failed.RuleID,
			Message: r.Failed.Message,
		}
	} else {
		rec.Status = StatusSuccess
	}
	return rec
}

// Common errors.
var (
	ErrNotFound     = errors.New("record not found")
	ErrStoreCorrupt = errors.New("index store corrupt")
)
