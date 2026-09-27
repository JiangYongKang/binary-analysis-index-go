# 本地二进制样本分析索引 — 设计说明

## 1. 支持的格式范围

| 格式 | 支持情况 | 解析内容 |
| --- | --- | --- |
| ELF | ELF32 / ELF64，小端与大端；`ET_EXEC/ET_DYN/...` | 架构、入口、节表（名称/大小/标志/原始数据/香农熵）、UPX 风格节标记、`PT_DYNAMIC` 中的 `DT_NEEDED` |
| PE | PE32 / PE32+（主要验证 PE32+），小端 x86/amd64/arm64 | 架构、入口、镜像类型（exe/dll）、节表与熵、UPX 风格节标记、完整导入目录（DLL + 符号，支持序号导入） |

不支持的情况**显式报错**，绝不静默跳过。错误分类（`binfmt.FailureKind`，可通过 `binfmt.IsKind` 区分）：

- `unrecognized`：魔数既不是 `\x7fELF` 也不是 `MZ`（含空文件、纯文本）；
- `truncated`：头部/节表/节数据/导入目录声称的范围超出实际文件（文件被截断）；
- `corrupt`：魔数正确但内部结构非法（如 PE 签名错误、`e_shstrndx` 越界、导入 RVA 不落在任何节内）；
- `unsupported`：识别为 ELF/PE，但子格式不支持（如非法 `EI_CLASS`、无可选头的 PE 目标文件）。

每个错误都携带 `Format / Offset / Context` 等可定位上下文，并实现 `Unwrap` 保留底层错误。
规则自身执行失败由 `*rules.RuleError` 表示（携带规则 ID 与规则版本），与解析错误明确区分。

## 2. 组件

- `pkg/binfmt`：二进制解析器与类型化错误，不依赖任何外部扫描工具。
- `pkg/samplegen`：测试期生成**最小但结构合法**的 ELF64 / PE32+ 样本，
  以及 `TruncateAt`（物理截断）和 `Corrupt`（class / section-offset / shstrndx /
  coff-signature / rva）变体；高熵数据使用固定种子，跨进程可复现。
- `pkg/rules`：不可变规则集与引擎。内置两个版本：
  - `1.0.0`：`PACKED_001`（UPX 风格高熵节，熵阈值 6.5）、`PE_IMPORTS_001`（宽口径导入检查）；
  - `2.0.0`：`PACKED_001`（阈值收紧到 7.0）、`PE_IMPORTS_002`（逐 API 严口径，缺 `WriteFile` 即命中）、新增 `PE_DOTNET_002`。
  规则集发布后不可变，未知版本显式报错，不静默回退。
- `pkg/index`：分析索引。内容寻址（SHA-256）、版本化记录（`<contentID>@<ruleVersion>`）、
  并发去重（自定义 singleflight）、快照隔离存储（`MemoryStore` / `FileStore`）。

## 3. 增量与版本兼容规则

- **内容寻址**：样本以全部字节的 SHA-256 作为 `ContentID`，与文件名无关；
  相同内容 + 相同规则版本已有结论时直接复用，**绝不重复分析**，失败结论同样缓存复用。
- **版本共存**：记录键包含规则版本。同一内容在 v1、v2 下各有一条不可变记录，互不覆盖；
  `Get` 取索引绑定版本，`GetForVersion(id, version)` 可取回任意历史版本结论，旧结果可复现。
- **只增不改的规则版本**：新版本 = 新引擎 + 新版本号；`Record.RuleVersion` 明确标识结论所用规则版本，
  `Basis` 字段给出可读判定依据（命中了哪些规则 / 为什么是 clean）。
- **失败也是结论**：解析失败产生 `StatusFailed` 记录，`Failure.Kind` 可区分原因；
  调用方不会因为输入损坏而得到"静默成功/空结果"。

## 4. 并发与一致性语义

- **同目标并发去重**：同一 `contentID@version` 的并发请求合并为一次实际分析，
  所有等待者共享同一结果对象，结论必然一致。提交在存储临界区内还有一道存在性检查，
  三重保证（读快照 → singleflight → 提交临界区）杜绝重复或矛盾记录。
- **取消/超时隔离**：分析在脱离调用方 `ctx` 的生命周期中运行
  （`context.Background()`）。请求取消或超时只让**该次调用**提前返回 `ctx.Err()`；
  分析继续运行到完成并原子提交，因此：不污染索引、不产生半成品、不会"因为某人取消而丢结论"。
- **快照隔离**：`Store.Commit` 在互斥临界区内 read-modify-write，一次性整体替换快照；
  `Snapshot` 返回独立 map。读端任何时刻只能看到**完整旧状态**或**完整新状态**，
  看不到半新半旧。
- **崩溃安全的持久化**：`FileStore` 更新协议为
  写临时文件 `<path>.tmp.<pid>` → `fsync` → 原子 `rename`。
  - rename 前掉电：主文件仍是旧快照，遗留的临时文件在下次 `NewFileStore` 时被清除；
  - rename 后掉电：新快照已经完整生效。
  `SetCrashHook` 可在 rename 前注入故障用于测试"更新中断后的恢复"。

## 5. 审计日志

索引接受任意 `Logger`。每次分析打印一行结构化日志，包含：
样本名、内容标识（前 12 位）、格式、规则版本、状态、命中规则 ID 列表与最终判定依据；
失败时打印失败分类与定位上下文。测试中通过 `t.Logf` 输出，`go test -v` 可见。

## 6. 验证方法

```bash
go test ./...                 # 全量单测
go test -race -count=1 ./...  # 竞态检测
go test -v ./pkg/index/       # 查看含样本标识/命中规则/判定依据的审计日志
```

测试场景与需求对应关系：

| 需求 | 测试 |
| --- | --- |
| ELF/PE 基础解析与结构化标记 | `binfmt.TestParseELF64`、`binfmt.TestParsePE32Plus` |
| 损坏/截断/不支持可区分且带上下文 | `binfmt.TestParseErrorsAreDistinguishable`、`binfmt.TestParseErrorContext`、`index.TestFailuresAreExplicitAndDistinguishable` |
| 规则执行失败不被静默 | `rules.TestRuleExecutionFailureIsExplicit`、`index.TestRuleFailureProducesFailedRecord` |
| 增量不重复分析 | `index.TestIncrementalDoesNotReanalyze` |
| 并发重复扫描结果一致、无重复记录 | `index.TestConcurrentDuplicateScanIsConsistent`、`index.TestConcurrentMixedCancel` |
| 取消/超时不污染索引、不留半成品 | `index.TestCanceledRequestDoesNotPolluteIndex`、`index.TestConcurrentMixedCancel` |
| 规则升级共存、旧结果可复现 | `rules.TestV1AndV2CoexistAndDiffer`、`index.TestRuleUpgradeCoexistence` |
| 更新只能看到完整旧/新状态 | `index.TestSnapshotIsolationUnderConcurrentUpdates` |
| 更新中断恢复、无悬空记录 | `index.TestFileStoreCrashBeforeRenameRecovery`、`index.TestFileStoreRoundTrip` |
| 样本生成确定性 | `samplegen.TestGeneratorsDeterministic` 等 |

## 7. 使用示例

```go
store := index.NewMemoryStore()              // 或 index.NewFileStore("index.json")
engine, _ := rules.BuiltinEngine(rules.Version2)
idx := index.New(index.Config{Engine: engine, Store: store, Logger: index.StdLogger()})

rec, err := idx.Analyze(context.Background(), "sample.exe", data)
// rec.Status: ok/failed；rec.Verdict: clean/suspicious；rec.Matches：命中规则；
// rec.Failure：可区分的失败原因；rec.Basis：最终判定依据
```
