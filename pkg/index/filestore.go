package index

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileStore 把全部记录持久化为单个 JSON 快照文件。
// 更新协议（崩溃安全）：
//  1. 在同目录写临时文件 <path>.tmp.<pid>，写完并 flush/fsync；
//  2. （可注入崩溃点，模拟 write 后 rename 前掉电）
//  3. rename 原子替换目标文件；
//
// 因此任何时刻：要么旧文件完好，要么新文件完整，绝不会出现半新半旧。
// 启动时若发现遗留临时文件，一律删除（它从未被 rename，不代表任何已提交状态）。
type FileStore struct {
	mu        sync.Mutex
	path      string
	crashHook func() error
}

// NewFileStore 打开（不存在则惰性创建）基于文件的存储，并清理上次崩溃遗留的临时文件。
func NewFileStore(path string) (*FileStore, error) {
	if filepath.Clean(path) == "." || path == "" {
		return nil, errors.New("filestore: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("filestore: create parent dir: %w", err)
	}
	s := &FileStore{path: path}
	if err := s.recoverStaging(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		// 初始化为空快照
		if err := s.writeSnapshot(map[string]*Record{}); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// SetCrashHook 注入故障：临时文件已写入并 fsync、rename 之前调用。
// hook 返回 error 时模拟该阶段崩溃——保留临时文件、不执行 rename。
func (s *FileStore) SetCrashHook(hook func() error) {
	s.mu.Lock()
	s.crashHook = hook
	s.mu.Unlock()
}

func (s *FileStore) stagingPattern() string { return s.path + ".tmp.*" }

// recoverStaging 删除所有未完成 rename 的临时文件（更新中断后的恢复入口）。
func (s *FileStore) recoverStaging() error {
	matches, err := filepath.Glob(s.stagingPattern())
	if err != nil {
		return fmt.Errorf("filestore: scan staging files: %w", err)
	}
	for _, m := range matches {
		if err := os.Remove(m); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("filestore: remove stale staging file %s: %w", m, err)
		}
	}
	return nil
}

func (s *FileStore) readSnapshot() (map[string]*Record, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("filestore: read snapshot: %w", err)
	}
	var m map[string]*Record
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("filestore: snapshot corrupt after recovery: %w", err)
	}
	if m == nil {
		m = map[string]*Record{}
	}
	return m, nil
}

func (s *FileStore) writeSnapshot(m map[string]*Record) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("filestore: encode snapshot: %w", err)
	}
	tmp := fmt.Sprintf("%s.tmp.%d", s.path, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("filestore: create staging file: %w", err)
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("filestore: write staging file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("filestore: fsync staging file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("filestore: close staging file: %w", err)
	}
	if s.crashHook != nil {
		if herr := s.crashHook(); herr != nil {
			// 模拟掉电：临时文件保留，rename 不发生，返回带上下文的错误。
			return fmt.Errorf("filestore: injected crash before rename (staging=%s kept): %w", tmp, herr)
		}
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("filestore: atomic rename: %w", err)
	}
	return nil
}

// Snapshot 返回磁盘当前快照的深拷贝。
func (s *FileStore) Snapshot(_ context.Context) (map[string]*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readSnapshot()
	if err != nil {
		return nil, err
	}
	return cloneSnapshot(m), nil
}

// Commit 在互斥临界区内读快照、应用变更、原子替换。
// 任何一步失败都保留旧文件，不会留下被引用的半成品。
func (s *FileStore) Commit(ctx context.Context, mutate func(cur map[string]*Record) (map[string]*Record, error)) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.readSnapshot()
	if err != nil {
		return err
	}
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("commit mutate panicked: %v", p)
		}
	}()
	next, merr := mutate(cur)
	if merr != nil {
		return merr
	}
	if next == nil {
		next = map[string]*Record{}
	}
	return s.writeSnapshot(next)
}

// Close 释放资源（FileStore 无后台资源）。
func (s *FileStore) Close() error { return nil }
