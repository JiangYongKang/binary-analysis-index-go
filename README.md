# binary-analysis-index-go

本地二进制样本的**结构化解析 + 规则标记 + 可持久化索引**。纯 Go 实现，零第三方依赖；
测试样本在测试运行时由代码合成，不调用任何外部扫描器、网络服务或真实凭据。

## 1. 支持的格式范围

| 格式 | 支持情况 | 解析内容 |
|------|----------|----------|
| ELF (`\x7fELF`) | ELF32 / ELF64，小端与大端 | ELF 头（类型、架构、入口）、节区表、节名、是否 strip |
| PE (`MZ` + `PE\0\0`) | PE32 / PE32+ | DOS 头、COFF 头、可选头（架构、入口、子系统、调试目录）、节区表、是否 strip |
| Mach-O / 胖 Mach-O | **不支持，但显式报错** | —— |
| 其它魔数 / 空文件 | 不可解析，显式报错 | —— |

解析只读取结构化头部所需的字节，不执行、不加载样本内容。

### 错误分类（不会静默跳过任何文件）

解析失败统一返回带原因与定位上下文（文件、字节偏移、细节）的 `binaryfmt.ParseError`，
分析层再映射为四类**可区分**的失败：

| 失败类型 | 含义 |
|----------|------|
| `unsupported_format` | 空文件、未知魔数，或已知但不支持的格式（Mach-O） |
| `truncated` | 头部魔数可识别，但其声明的结构（节表/节数据/PE 头偏移）超出文件末尾 |
| `corrupt` | 魔数可识别但头部字段非法（如 ELF `EI_CLASS` 非 1/2、PE 签名缺失、可选头魔数未知、节名字符串越界等） |
| `rule_execution` | 样本解析成功，但某条规则求值返回错误；分析立即中止并记录肇事规则 ID |

> 「截断」与「损坏」被刻意区分：前者是文件被切短（结构合法但数据缺失），后者是结构本身自相矛盾。

规则失败不是普通错误返回，而是一条 `status=failed` 的记录，包含 `kind=rule_execution`
与 `rule_id`，与样本解析失败一样会被缓存、可查询、可复现。

## 2. 增量分析与版本兼容规则

### 内容寻址

- 样本身份 = 文件内容的 **SHA-256**；两个文件名不同但字节相同的文件是同一个样本。
- 索引键 = `(sampleID, ruleVersion)` 复合键。
- 成功结果与已分类失败结果都会缓存：相同内容 + 相同规则版本**永不重复分析**，
  也不会因为换了文件名而重算。

### 规则版本共存

- 规则集（`rules.Set`）不可变，并带版本标签；注册表中同一版本不可重复注册
  （`ErrVersionExists`），从机制上保证旧结果可复现。
- 不同版本的结果**并排保存**。内置规则：
  - `builtin-2026.1`（v1）：`format.classified`、`format.pe-gui`（均为 info），
    所有可解析样本判定为 `clean`。
  - `builtin-2026.2`（v2）：在 v1 基础上新增 `elf.stripped`（warning）。
    于是 strip 过的 ELF 在 v1 下仍是 `clean`，在 v2 下为 `suspicious`；
    两份结论都可查询，每条记录都显式标注 `rule_version`。
- 判定依据可追溯：每条记录包含命中规则列表和 `basis`（例如
  `"warning rules matched: elf.stripped"`）。
- 判定规则确定且无随机性：存在任意 warning 命中即 `suspicious`，否则 `clean`。

升级工作流：注册新版本规则集（旧版本保留）→ 对样本以新版本 `scan` →
`LookupAnyVersion(sampleID)` 同时拿到新旧版本结论。

## 3. 并发与一致性语义

### Single-flight 去重

- 对同一 `(sampleID, ruleVersion)` 的并发请求只执行**一次**分析，所有调用方共享同一结果
  （同一个 `*Record` 指针，结论不可能互相矛盾）。
- 共享分析运行在**脱离任何单个调用方生命周期**的 context 上：
  - 某个调用方超时/取消，只会放弃自己的等待（收到自己的 `context.DeadlineExceeded`）；
  - 共享分析继续进行，完成后照常提交；
  - 取消不会写入半成品记录、不会污染索引、不影响其它等待者。
- 分析过程中逐规则响应取消；取消时只返回 `error`，不返回任何部分结果。

### 快照一致性

- 索引状态是**不可变快照**（`Snapshot`）。更新时克隆当前快照、插入新记录、生成新一代，
  然后一次性替换状态指针；读者要么看到完整的旧一代，要么看到完整的新一代，
  绝不会看到「半新半旧」。
- 查询接口返回快照的深拷贝，读者长时间持有的数据不受后续更新影响。

### 持久化与崩溃恢复

- 持久化采用 **临时文件 + fsync + rename**：先把新快照写到同目录
  `index.json.tmp-*`，落盘后原子改名为 `index.json`。
- 提交顺序是**先持久化、后发布**：持久化失败则保留完整旧状态并返回错误，
  绝不会出现「内存已更新但磁盘没有」的状态。
- 更新中断（进程被杀 / 机器断电）后重新打开：
  - rename 已完成 → 读到完整新快照；
  - rename 未完成 → 旧快照原封不动，遗留的 `*.tmp-*` 会被忽略并尽力清理；
  - 不产生重复记录或悬空记录（加载时还会校验 map 键与记录键一致）。
- 失败也落盘：损坏样本、规则失败的记录同样持久化，重启后无需重新分析。

## 4. 代码结构

```
internal/binaryfmt  手工 ELF/PE 解析与可区分错误（无 debug/* 依赖）
internal/rules      规则、规则集、版本注册表、内置 v1/v2、可注入的 FailingRule
internal/analysis   单样本分析编排：解析 -> 规则求值 -> 判定/依据，上下文取消
internal/index      内容寻址缓存、single-flight、不可变快照、原子持久化与恢复
internal/scan       打开文件/算哈希，桥接 analysis 与 index
internal/samples    测试期合成 ELF/PE 及截断/损坏/不支持样本
cmd/baidx           命令行入口
```

## 5. 验证方法

### 运行全部测试

```sh
go test -race -count=1 ./...
go vet ./...
```

测试覆盖（样本全部由 `internal/samples` 现场生成）：

- **损坏输入**：截断 ELF/PE、损坏 ELF 头、未知魔数、Mach-O、空文件 ——
  断言四种失败原因可区分、带偏移上下文，且失败被缓存不重算
  （`TestParseSmoke`、`TestCorruptInputsAreClassifiedAndCached`、
  `TestAnalyzeVerdictsAndBasis`）。
- **规则执行失败**：注入 `FailingRule`，断言产生 `rule_execution` 失败记录并带规则 ID
  （`TestRuleExecutionFailureIsRecorded`、`TestRuleFailureAborts`）。
- **并发重复扫描**：32 个 goroutine 同时扫描同一目标，断言分析只执行一次、
  结果指针完全相同、索引只有一条记录（`TestConcurrentDuplicateScan`，
  另有 scan 包 16 并发端到端版本）。
- **内容寻址增量**：同内容不同文件名只产生一条记录；重复扫描不重算
  （`TestIncrementalNoReanalysis`、`TestContentAddressing`）。
- **规则升级共存**：同一样本在 v1 下 `clean`、v2 下 `suspicious`，两版记录并存且可复现
  （`TestRuleVersionCoexistence`、`TestEndToEndConcurrentAndVersions`）。
- **取消隔离**：等待方超时后索引中无半成品；共享分析完成后仍只提交一次
  （`TestCancelledCallerDoesNotPollute`、`TestCancellationReturnsNoResult`）。
- **更新期间一致性**：一个 goroutine 高频读取快照，另一个不断提交更新，
  断言代际单调、每条记录完整、最终无重复/悬空记录
  （`TestSnapshotConsistencyDuringUpdates`）。
- **更新中断恢复**：预置一份完整快照 + 一个半截子临时文件，断言恢复后只有旧完整状态、
  后续成功保存后目录中不留临时文件（`TestInterruptedUpdateRecovery`）。
- **持久化往返**：重启后已存记录不重算（`TestPersistenceRoundTrip`）。
- **CLI 黑盒**：`TestCLI` 直接驱动命令行，校验扫描、失败分类、版本升级、list 与增量输出。

测试日志按要求打印**样本标识（内容哈希前缀）、命中规则与最终判定依据**，例如：

```
sample=bbbb027151c1 ... rules=builtin-2026.1 hits=[format.classified:info] FINAL=clean basis="no warning rules matched; ..."
sample=bbbb027151c1 ... rules=builtin-2026.2 hits=[format.classified:info elf.stripped:warning] FINAL=suspicious basis="warning rules matched: elf.stripped"
sample=73bfe8015bb0 ... rules=builtin-2026.1 FINAL=status:failed reason=truncated offset=76 detail="ELF section header table offset 76 is outside the file"
```

### 命令行体验

```sh
go run ./cmd/baidx versions
go run ./cmd/baidx -index /tmp/idx.json scan -rules builtin-2026.2 path/to/sample
go run ./cmd/baidx -index /tmp/idx.json list
go run ./cmd/baidx -index /tmp/idx.json get -sample <sha256> [-rules builtin-2026.1]
```

`-index` 可位于子命令前后；不指定时默认为 `.baidx/index.json`。

## 6. 设计边界（明确不做的事）

- 不做反汇编、签名库匹配、YARA/ClamAV 之类外部工具集成。
- 不做联网查询、云提交或任何需要凭据的操作。
- 解析器只覆盖头部与节表结构，足以做结构化标记；不声称是完整的格式校验器。
