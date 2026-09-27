# binary-analysis-index-go

本地二进制样本分析索引：对本地 ELF / PE 样本做基础解析、规则化标记，并把结论作为
**内容寻址、规则版本化、快照一致**的记录保存。纯 Go 标准库实现，测试样本在测试时生成，
不依赖外部扫描工具、在线服务或真实凭据。

## 能力一览

- **格式**：ELF32/64（双端序）、PE32/PE32+；解析头部、节表（含熵）、UPX 风格加壳标记、PE 导入表。
- **显式错误**：无法解析 / 截断 / 损坏 / 格式不支持 / 规则执行失败全部类型化返回并落记录，原因可区分、带文件偏移上下文，绝不静默跳过。
- **增量分析**：以 SHA-256 内容标识去重，同内容同规则版本只分析一次（成功和失败结论都复用）。
- **并发一致**：同目标并发请求合并为一次分析；结果一致、无重复记录；单个请求取消/超时不影响进行中的分析，不留半成品。
- **规则版本共存**：不可变规则集 `1.0.0` / `2.0.0`；新旧结论同库存放、可按版本复现，每条记录标注规则版本与判定依据。
- **快照隔离 + 崩溃恢复**：内存或单文件存储；文件存储采用临时文件 + fsync + 原子 rename，更新中断后自动清理孤儿临时文件。

## 快速开始

```go
eng, err := rules.BuiltinEngine(rules.Version2) // 或 rules.Version1
if err != nil { log.Fatal(err) }
store, err := index.NewFileStore("data/index.json") // 也可用 index.NewMemoryStore()
if err != nil { log.Fatal(err) }
idx := index.New(index.Config{Engine: eng, Store: store, Logger: index.StdLogger()})

rec, err := idx.Analyze(ctx, "sample.exe", fileBytes)
switch {
case err != nil:            // 仅在存储/系统层失败时返回错误（如 ctx 已取消）
case rec.Status == index.StatusFailed:
    fmt.Println(rec.Failure.Kind, rec.Failure.Offset, rec.Failure.Context)
case rec.Verdict == rules.VerdictSuspicious:
    fmt.Println(rec.Matches, rec.RuleVersion, rec.Basis)
default:
    fmt.Println("clean:", rec.Basis)
}
```

查询：

```go
idx.Get(ctx, contentID)                                   // 当前规则版本
idx.GetForVersion(ctx, contentID, rules.Version1)         // 复现历史版本结论
index.ContentID(data)                                      // SHA-256 内容标识
```

## 验证

```bash
go test ./...                  # 全量单测（样本均在测试中由 pkg/samplegen 生成）
go test -race -count=1 ./...   # 竞态检测
go test -v ./pkg/index/        # 打印样本标识、命中规则、最终判定依据的审计日志
```

覆盖：损坏/截断/不支持输入、并发重复扫描、规则升级共存、取消隔离、更新中断恢复、快照隔离。

## 文档

- 设计与语义细节：[docs/design.md](docs/design.md)
