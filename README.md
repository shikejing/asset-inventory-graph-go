# 内网资产清单引擎（asset-inventory-graph-go）

把多路扫描来源（nmap / agent / CMDB / 被动扫描 / 回环推送……）产出的**重复且互相矛盾**的原始
资产记录，收敛成**唯一资产清单**并维护**资产关系图**。整条链路只使用内存管道与本地回环，
**不依赖任何外部服务**，可在本地直接复现与验证。

## 快速开始

```bash
# 运行演示：内存来源 + 本地回环来源，含冲突裁决/幂等/全量重建/落盘
go run ./cmd/asset-demo -db /tmp/asset-inventory.log -reset

# 再运行一次（不加 -reset）：进程“重启”后从日志完整还原同一清单
go run ./cmd/asset-demo -db /tmp/asset-inventory.log

# 全部自动化测试（含 -race 并发检测）
go test ./...
go test -race ./...
```

## 能力对照

| # | 需求 | 实现位置 |
|---|------|----------|
| 1 | 多来源归一化、稳定标识去重、顺序无关 | `normalize/`（归一化 + 并查集）、`engine` 聚合 |
| 2 | 属性冲突按来源优先级/规则裁决，冲突可追溯不丢弃 | `merge/`、`model.Attribute.History` |
| 3 | 资产关系图构建/查询、更新自洽、环安全 | `graph/` |
| 4 | 乱序/重复/迟到的幂等增量应用 | 内容幂等键 + 确定性全序重算 `engine` |
| 5 | 全量重建与增量并存，重建期间变更不丢失 | `Engine.Rebuild`（提交锁 + 原子压实日志） |
| 6 | 并发摄入与无锁快照查询，慢来源不阻塞 | `engine`（互斥提交 + `atomic.Pointer` 快照）、`source.Runner`（fan-in） |
| 7 | 持久化与崩溃恢复，无半写状态 | `store.FileStore`（校验和帧 + fsync + temp/rename） |
| 8 | 自动化测试与文档 | 各包 `*_test.go`、本 README |

## 架构

```
 RawRecord(nmap/agent/cmdb/...)     本地回环 TCP（source.LoopbackServer）
        │ 内存 channel                      │ 按行 JSON
        └──────────────┬───────────────────┘
                       ▼
              source.Runner（每来源一个 goroutine，fan-in，慢来源互不阻塞）
                       ▼
        Engine.Ingest / IngestBatch
          1. Normalize 归一化 + 计算记录内容幂等键
          2. FileStore.Append（校验和帧 + fsync）—— 先持久化
          3. 从全量观察确定性重算（并查集 + 冲突合并 + 关系图）
          4. atomic.Pointer 发布新快照 —— 后发布
                       ▼
            Snapshot（只读已提交版本，无锁查询）
```

## 1. 去重语义

### 稳定标识

归一化（`normalize.Normalize`）是**纯函数**，相同输入永远得到相同输出：

- 主机名：转小写、去首尾空白与根尾点（`.`）→ `host:<name>`；
- IP：`net.ParseIP` 规范化 → `ip:<ip>`；
- CIDR：取掩码规范形式（如 `10.0.0.0/24`），**只保留为网段属性，不参与资产等价合并**，
  避免把整段网络错误合成一个资产；
- 服务：`port + 协议`（缺省 `tcp`）→ `tcp/22` 这样的稳定键；
- 漏洞：`vuln:<CVE 或来源编号>`；无编号时按标题+描述内容哈希；
- 弱口令：`cred:<port>/<sha10(user|auth|detail)>`，内容寻址天然去重。

### 等价合并（并查集）

同一条观察中出现的所有 `ip:`/`host:` 标识被 union 成同一资产；标识关系可**传递**：

```
观察A: host:h1  <-> ip:10.0.0.9
观察B: ip:10.0.0.9 <-> ip:10.0.0.10
观察C: ip:10.0.0.10 <-> host:h2
=> 四个标识属于同一个资产
```

并查集的组件代表**永远取成员中字典序最小者**，因此：

- 组件（即资产身份）只取决于标识集合，**与 union/到达顺序无关**；
- 对外稳定标识 `Asset.PrimaryID = 组件最小成员`，内部 `Asset.ID = 组件根`。

### 记录级幂等键

每条记录以其**规范序列化内容**（字段排序、主机名/服务排序后）取 SHA-256 得到
`DedupKey`。重复、乱序、迟到到达的同一条扫描结果只生效一次；重复应用整批变更，
清单结论与版本都不变。

### 为什么增量结果恒等于全量结果

每次提交都从**全部已提交观察**重新执行：建并查集 → 按组件聚合 → 确定性合并 → 重建图。
由于合并比较是全序、所有集合/遍历都排序，结果是观察集合的纯函数，与提交顺序无关；
迟到的更旧记录无法翻转既有裁决。

## 2. 冲突合并规则与可追溯性

单值属性（如 `os`、`domain`、服务 `name/product/version/banner`、漏洞标题/严重度）：
`Merger.MergeScalar` 按策略裁决出一个 `Winner`，并在 `History` 中**按裁决顺序保留全部来源
依据**（含胜者），冲突永不静默丢弃。多值属性（`hostnames`、`ipnets`）用 `MergeSet`
按值分组，每个值记录给出它的所有来源。

裁决比较器是**全序**的，保证与到达顺序无关：

- `source_priority`（默认）：`来源优先级 ↓` → `时间戳 ↓（新者优先）` → `值字典序 ↑`；
- `latest`：`时间戳 ↓` → 来源优先级 → 值兜底；
- `merge_set`：值集合合并 + 每值来源列表。

相同 `(来源, 值)` 的重复观察只保留一条（取更新时间戳）。

### 配置项（`merge.Config`）

```go
type Config struct {
    SourcePriority  map[string]int   // 来源 -> 优先级，数值越大越优先；未配置为 0
    Strategies      map[string]Strategy // 属性键 -> 策略
    DefaultStrategy Strategy            // 未列出的属性使用，默认 source_priority
}
```

默认优先级（`merge.DefaultConfig()`）：`cmdb=100 > agent=90 > nmap=50 > passivescan=30`。

可配置的属性键：

| 键 | 默认策略 | 含义 |
|----|----------|------|
| `os` | `source_priority` | 操作系统 |
| `domain` | `source_priority` | 归属域 |
| `hostnames` | `merge_set` | 主机名集合 |
| `ipnets` | `merge_set` | IP/网段集合 |
| `svc.name` | `source_priority` | 服务名 |
| `svc.version` | `latest` | 服务版本 |
| `svc.product` | `source_priority` | 服务产品 |
| `svc.banner` | `latest` | 服务指纹 |
| `vuln.title` / `vuln.severity` | `source_priority` | 漏洞标题/严重度 |

查询示例（演示输出）：`OS="RHEL 7" 依据=cmdb@120="RHEL 7" < agent@90="CentOS 7 ..." < nmap@100="Linux 3.x"`。

## 3. 关系图

节点类型：`asset / service / vuln / weakcred / domain`。边类型：

- `asset -> service`、`service -> vuln`、`service -> weakcred`、
  `asset -> vuln`（资产级漏洞）、`asset -> domain`。

服务节点 ID 为 `svc:<assetID>:<port/proto>`，保证跨资产不串边。图在**每次提交时整图重建**，
因此资产新增/合并/更新后关联关系自动同步且自洽。查询能力：

- `Snapshot.AssetRelations(id)`：资产可达的全部关系节点（DFS + visited）；
- `Snapshot.DomainAssets(domain)`：反向边查归属域下资产；
- `Snapshot.FindByIP/FindByHostname/GetAsset/ListAssets/Stats`。

所有遍历与统计都以 visited/三色标记驱动，**图中出现环也不会死循环**
（`Graph.DetectCycle` / `CycleCount` 可报环），并有专门的带环图测试。

## 4. 增量幂等与全量重建

- 增量：`Ingest` / `IngestBatch`，基于内容幂等键去重；
- 重建：`Rebuild()` 先用 `temp + fsync + rename + fsync(dir)` **原子压实**日志，再从全部
  观察重算。重建在提交锁内进行，期间到达的摄入阻塞等待、随后依次应用，**变更不丢失**；
  因为重算确定，重建完成后的清单与关系图等价于“把含等待中变更在内的全部记录一次性全量重放”，
  结果可解释、可重复。

## 5. 并发与一致性

- 提交侧：一把互斥锁串行化提交，多来源并行摄入时同一资产**不会重复创建或互相覆盖**；
- 查询侧：已发布快照用 `atomic.Pointer` 保存不可变的资产表与图，查询**无锁**、总是读到
  某个完整已提交版本，慢来源的 fsync/处理**不阻塞查询推进**；
- 来源侧：`Runner` 采用 fan-in——转发协程只读 channel，提交只在主循环按批进行，
  避免“持锁等待时来源无法排空/关闭”的死锁；
- 提交顺序为“**先持久化成功，后发布内存版本**”，失败可安全重试，不残留半提交。

## 6. 持久化与崩溃恢复

`store.FileStore` 为只增 JSONL 日志，每行一帧 `{c: sha256(payload), p: payload}`：

- `Append` 后 `fsync`；崩溃最多损失最后一帧的**残缺部分**，重启时校验失败的尾帧被
  识别并截断，不会出现“写了一半”的资产或关系；
- `Load` 重放全部完整帧即可还原已提交清单与关系图；未完成（未 fsync）的摄入不在日志中，
  自然不残留；
- `ReplaceAll`（重建）走同目录临时文件 + fsync + rename + 目录 fsync，原子替换；
- `store.MemoryStore` 提供语义一致的内存实现，用于无盘演示与测试。

## 包结构

```
model/     原始记录、收敛资产、属性溯源、边等领域类型
normalize/ 归一化、稳定标识、记录幂等键、并查集
merge/     来源优先级与合并策略、全序冲突裁决、集合合并
graph/     关系图构建、环安全遍历、环检测、统计
store/     FileStore（崩溃安全日志）与 MemoryStore
engine/    引擎：摄入/重建/恢复/MVCC 快照、查询与统计
source/    内存模拟来源、本地回环 TCP 来源、并发 Runner
cmd/asset-demo  端到端可运行演示
```

## 测试覆盖

- 多来源去重与顺序无关、传递别名合并（`engine_test.go`、`normalize_test.go`）；
- 属性冲突裁决、被覆盖依据保留、策略差异、重复折叠（`merge_test.go`）；
- 乱序/重复/迟到增量结果恒等于全量结果（`TestIdempotentOutOfOrderLate`）；
- 16 goroutine 并发摄入同一资产 + 并发热查询（`-race`）；
- 全量重建等价性、重建期间变更不丢失、重复重建幂等；
- 重启恢复一致性、日志坏帧截断、原子替换（`store_test.go`、`TestRestartRecovery`）；
- 本地回环端到端、慢来源不阻塞、ctx 取消（`source_test.go`）；
- 带环图遍历终止与环检测（`graph_test.go`）。
