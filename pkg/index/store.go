package index

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrNotFound 表示存储中不存在目标记录。
var ErrNotFound = errors.New("record not found")

// Store 是版本化记录的持久化抽象。
// 所有实现必须保证 Snapshot/Commit 串行化，使读端只能看到完整的旧快照
// 或完整的新快照（快照隔离），绝不会读到半新半旧的数据。
type Store interface {
	// Snapshot 返回当前全部记录的深拷贝；之后存储变化不影响返回值。
	Snapshot(ctx context.Context) (map[string]*Record, error)
	// Commit 在临界区内执行一次 mutate：
	//   - mutate 返回的新 map 将原子替换当前状态；
	//   - mutate 返回 error 或 panic 时整体中止，状态保持为提交前，不留半成品。
	Commit(ctx context.Context, mutate func(cur map[string]*Record) (map[string]*Record, error)) error
	// Close 释放资源。
	Close() error
}

// MemoryStore 是纯内存 Store（默认实现，也用于测试）。
type MemoryStore struct {
	mu   sync.RWMutex
	snap map[string]*Record
}

// NewMemoryStore 创建空内存存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{snap: map[string]*Record{}}
}

// Snapshot 返回当前记录的深拷贝。
func (s *MemoryStore) Snapshot(_ context.Context) (map[string]*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSnapshot(s.snap), nil
}

// Commit 串行执行 read-modify-write 并原子替换快照。
func (s *MemoryStore) Commit(ctx context.Context, mutate func(cur map[string]*Record) (map[string]*Record, error)) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	working := cloneSnapshot(s.snap) // 在副本上修改
	defer func() {
		if p := recover(); p != nil {
			// 不替换 s.snap：本次写入整体丢弃，并把 panic 转为普通错误返回
			err = fmt.Errorf("commit mutate panicked: %v", p)
		}
	}()
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	next, merr := mutate(working)
	if merr != nil {
		return merr // 旧状态原样保留
	}
	if next == nil {
		next = map[string]*Record{}
	}
	// Record 按约定不可变，因此提交时直接采用 mutate 返回的记录指针，
	// 保证“先分析者”和“后来复用者”拿到的是同一规范对象。
	s.snap = next
	return nil
}

// Close 释放内存存储资源（无后台资源）。
func (s *MemoryStore) Close() error { return nil }

func cloneSnapshot(in map[string]*Record) map[string]*Record {
	// 仅复制 map 本身；Record 按约定不可变，共享指针是安全的，
	// 也让“同一内容复用同一记录对象”的比较成立。
	out := make(map[string]*Record, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
