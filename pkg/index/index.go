package index

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/highcumontoa/binary-analysis-index-go/pkg/binfmt"
	"github.com/highcumontoa/binary-analysis-index-go/pkg/rules"
)

// Logger 是分析过程的审计日志接口。
// 单测要求打印：样本标识、命中规则、最终判定依据。
type Logger interface {
	Printf(format string, args ...any)
}

// discardLogger 丢弃所有日志。
type discardLogger struct{}

func (discardLogger) Printf(string, ...any) {}

// Index 是样本分析索引。一个 Index 绑定一个规则版本（引擎）；
// 多个不同规则版本的 Index 共享同一 Store 时，新旧版本的记录共存，互不覆盖。
type Index struct {
	engine *rules.Engine
	store  Store
	log    Logger
	group  *group
}

// Config 是 New 的配置。
type Config struct {
	Engine *rules.Engine
	Store  Store
	Logger Logger // 为空时丢弃日志
}

// New 创建绑定指定规则版本的索引。
func New(cfg Config) *Index {
	if cfg.Engine == nil {
		panic("index.New: nil Engine")
	}
	if cfg.Store == nil {
		cfg.Store = NewMemoryStore()
	}
	if cfg.Logger == nil {
		cfg.Logger = discardLogger{}
	}
	return &Index{engine: cfg.Engine, store: cfg.Store, log: cfg.Logger, group: newGroup()}
}

// RuleVersion 返回该索引绑定的规则版本。
func (idx *Index) RuleVersion() string { return idx.engine.Version() }

// Analyze 分析字节内容并返回版本化记录。
//
// 语义：
//   - 增量：相同 contentID + 相同规则版本已有记录时直接复用，绝不重复分析；
//   - 并发去重：同一内容同一版本的并发请求合并为一次分析，结果完全一致；
//   - 显式失败：解析/规则执行失败产生 StatusFailed 记录，原因可区分、上下文可定位；
//   - 取消隔离：调用方 ctx 取消/超时只让本次等待提前返回；分析在脱离调用方的
//     上下文里运行到完成并原子提交，因此不会污染索引，也不会留下半成品；
//   - 原子可见：提交通过 Store 的快照级 Commit 完成，读端只能看到完整旧状态或完整新状态。
func (idx *Index) Analyze(ctx context.Context, sampleName string, data []byte) (*Record, error) {
	id := ContentID(data)
	key := RecordKey(id, idx.engine.Version())

	// 快路径：已有结论直接复用。
	if rec, err := idx.lookup(ctx, key); err == nil {
		idx.log.Printf("[analyze] sample=%q id=%s rule=%s reused=true status=%s verdict=%s",
			sampleName, shortID(id), idx.engine.Version(), rec.Status, rec.Verdict)
		return rec, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	// 去重执行。fn 内部使用 context.Background()：分析与提交不随任何单个请求取消。
	run := func() (*Record, error) {
		return idx.group.do(key, func() (*Record, error) {
			// 拿到执行权后再查一次：可能前一个分组刚提交。
			if rec, err := idx.lookup(context.Background(), key); err == nil {
				return rec, nil
			}
			rec := idx.analyzeOne(sampleName, id, data)
			committed := rec
			cerr := idx.store.Commit(context.Background(), func(cur map[string]*Record) (map[string]*Record, error) {
				// 临界区内第三道检查：杜绝并发下重复/矛盾记录。
				if existing, ok := cur[key]; ok {
					committed = existing // 已存在：保留首个结论，忽略后到结果
					return cur, nil
				}
				cur[key] = rec
				return cur, nil
			})
			if cerr != nil {
				return nil, fmt.Errorf("commit result for %s: %w", shortID(key), cerr)
			}
			return committed, nil
		})
	}

	// 若调用方已取消，仍启动/合并分析，但不阻塞等待。
	if err := ctx.Err(); err != nil {
		go func() { _, _ = run() }()
		return nil, err
	}

	// 在 goroutine 中执行，使等待可被调用方取消，而分析本身不受影响。
	type result struct {
		rec *Record
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		rec, err := run()
		resCh <- result{rec, err}
	}()
	select {
	case r := <-resCh:
		return r.rec, r.err
	case <-ctx.Done():
		// 分析仍在后台运行并会提交；仅本次调用返回取消。
		idx.log.Printf("[analyze] sample=%q id=%s rule=%s wait canceled (%v); analysis continues detached",
			sampleName, shortID(id), idx.engine.Version(), ctx.Err())
		return nil, ctx.Err()
	}
}

// analyzeOne 执行单次解析 + 规则评估，任何失败都转换为显式的 StatusFailed 记录。
func (idx *Index) analyzeOne(sampleName, id string, data []byte) *Record {
	now := time.Now().UTC()
	base := &Record{
		ContentID:   id,
		SampleName:  sampleName,
		Size:        int64(len(data)),
		RuleVersion: idx.engine.Version(),
		AnalyzedAt:  now,
	}
	info, perr := binfmt.Parse(data, sampleName)
	if perr != nil {
		f := toFailure(perr)
		base.Status = StatusFailed
		base.Failure = &f
		idx.log.Printf("[analyze] sample=%q id=%s rule=%s status=failed kind=%s context=%q offset=%d",
			sampleName, shortID(id), idx.engine.Version(), f.Kind, f.Context, f.Offset)
		return base
	}
	matches, verdict, basis, rerr := idx.engine.Analyze(context.Background(), info)
	if rerr != nil {
		f := ruleFailure(rerr)
		base.Status = StatusFailed
		base.Failure = &f
		idx.log.Printf("[analyze] sample=%q id=%s rule=%s status=failed kind=rule_failed rule=%s context=%q",
			sampleName, shortID(id), idx.engine.Version(), f.RuleID, f.Context)
		return base
	}
	base.Status = StatusOK
	base.Verdict = verdict
	base.Matches = matches
	base.Basis = basis
	ids := matchIDs(matches)
	idx.log.Printf("[analyze] sample=%q id=%s format=%s rule=%s status=ok verdict=%s matched=%v basis=%q",
		sampleName, shortID(id), info.Format, idx.engine.Version(), verdict, ids, basis)
	return base
}

func toFailure(err error) Failure {
	var pe *binfmt.ParseError
	if errors.As(err, &pe) {
		f := Failure{
			Kind:     string(pe.Kind),
			Format:   pe.Format,
			Offset:   pe.Offset,
			Context:  pe.Context,
			Embedded: embedded(pe.Err),
		}
		return f
	}
	return Failure{Kind: "internal", Offset: -1, Context: "non-parse error", Embedded: err.Error()}
}

func ruleFailure(err error) Failure {
	var re *rules.RuleError
	if errors.As(err, &re) {
		return Failure{
			Kind:     "rule_failed",
			RuleID:   re.RuleID,
			Offset:   -1,
			Context:  fmt.Sprintf("rule %s failed under version %s", re.RuleID, re.Version),
			Embedded: embedded(re.Err),
		}
	}
	return Failure{Kind: "internal", Offset: -1, Context: err.Error(), Embedded: err.Error()}
}

func embedded(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func matchIDs(ms []rules.Match) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.RuleID)
	}
	sort.Strings(out)
	return out
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// lookup 取指定版本键的记录。
func (idx *Index) lookup(ctx context.Context, key string) (*Record, error) {
	snap, err := idx.store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	rec, ok := snap[key]
	if !ok {
		return nil, ErrNotFound
	}
	return rec, nil
}

// Get 查询某内容在当前索引规则版本下的记录；不存在返回 ErrNotFound。
func (idx *Index) Get(ctx context.Context, contentID string) (*Record, error) {
	return idx.lookup(ctx, RecordKey(contentID, idx.engine.Version()))
}

// GetForVersion 查询某内容在任意规则版本下的历史记录，用于复现旧结论。
func (idx *Index) GetForVersion(ctx context.Context, contentID, ruleVersion string) (*Record, error) {
	return idx.lookup(ctx, RecordKey(contentID, ruleVersion))
}

// All 返回当前快照中全部记录的副本（稳定排序：contentID 再 ruleVersion）。
// 读侧看到的始终是某一时刻完整一致的快照。
func (idx *Index) All(ctx context.Context) ([]*Record, error) {
	snap, err := idx.store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*Record, 0, len(snap))
	for _, r := range snap {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ContentID != out[j].ContentID {
			return out[i].ContentID < out[j].ContentID
		}
		return out[i].RuleVersion < out[j].RuleVersion
	})
	return out, nil
}

type stdLogger struct{}

func (stdLogger) Printf(format string, args ...any) { log.Printf(format, args...) }

// StdLogger 返回基于标准 log 包的 Logger，便于测试打印审计日志。
func StdLogger() Logger { return stdLogger{} }
