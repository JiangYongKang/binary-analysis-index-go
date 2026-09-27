package index

import "sync"

// call 表示一次进行中的分析及其等待者。
type call struct {
	done chan struct{}
	rec  *Record
	err  error
}

// group 是按 key 去重的单次执行组。
// 与 golang.org/x/sync/singleflight 的关键区别：
// 首个（领导）调用者即使提前取消等待，fn 仍会在脱离其 ctx 的生命周期中运行到完成
// 并由调用方决定是否提交；取消只让等待者提前返回，绝不污染索引或留下半成品。
type group struct {
	mu sync.Mutex
	m  map[string]*call
}

func newGroup() *group {
	return &group{m: map[string]*call{}}
}

// do 保证同一 key 同一时刻只有一次 fn 真正执行；同一时刻的其它调用共享结果。
// 注意 fn 接收的 ctx 是独立 ctx（见 Index.Analyze），本函数只负责去重与结果共享。
func (g *group) do(key string, fn func() (*Record, error)) (*Record, error) {
	g.mu.Lock()
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		<-c.done // 追随者等待同一个结果（期间自身 ctx 是否取消由调用方在外层处理）
		return c.rec, c.err
	}
	c := &call{done: make(chan struct{})}
	g.m[key] = c
	g.mu.Unlock()

	c.rec, c.err = fn()
	close(c.done)

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	return c.rec, c.err
}
