# 资产清单引擎（asset-inventory-graph-go）

面向内网资产梳理的资产清单引擎：多路扫描来源各自产出**原始资产记录**
（RawRecord），来源之间会重复覆盖同一个资产、字段互相矛盾，资产之间还存在
依赖与归属关系。引擎把多来源结果收敛成**唯一资产清单**并维护**资产关系图**。

整条链路不依赖任何外部服务：扫描来源用 goroutine + 内存 channel 模拟，
持久化只使用本地文件（WAL + 快照），可在本地完整复现与验证。

```
go test ./...        # 自动化测试
go run ./cmd/demo    # 多来源内存管道模拟演示
```

## 1. 去重语义（稳定标识收敛）

每个原始记录携带一组**身份声明**（identity claim）：

- 归一化主机名：小写、去首尾空白、去掉末尾 `.`（`web-01.` → `web-01`）；
- 归一化 IP：`net.ParseIP` 规范化（`10.0.0.1` 与 `10.0.0.1` 等价）；
- 归一化 MAC：小写、仅保留十六进制位；
- 三者皆无：退化为按记录 ID 收敛（`rec:<record-id>`）。

身份声明带命名空间（`hn:` / `ip:` / `mac:`），互相不会碰撞。

收敛算法是身份键上的**并查集**：一条记录携带的任意身份键若已属于某个
资产组件，就并入该组件；若一条记录同时命中两个组件，则把两个组件合并。
最终资产 ID 由组件的身份键集合直接派生
（`sha1(排序后的键)`），因此：

- **去重结果与来源到达顺序无关**（乱序、重复、迟到都不影响最终清单）；
- 同一资产在不同来源下的主机名（FQDN vs 短名）、网段、服务、端口都收敛
  到唯一资产；
- 资产的 IP / MAC / 端口 / 服务取并集，跨来源互补。

## 2. 属性冲突合并与可追溯

单值属性（`hostname`、`os`、`domain`、`version` 以及自定义 `attr.*`）在
来源间取值不同时，按**可配置的合并规则**裁决：

| 策略 | 行为 |
| --- | --- |
| `priority`（默认） | 取优先级最高来源的值；平局按更新时间、来源 ID 排序 |
| `latest` | 取观测时间最新的值 |
| `first` | 取最早观测到的值（适合主机名这类稳定标识，避免反复跳变） |
| `union` | 多值属性收集全部观测（端口、服务、弱口令、漏洞天然并集） |

配置方式：

```go
cfg := inventory.DefaultConfig()
cfg.SourcePriority = map[inventory.SourceID]int{
    "netscan": 1,   // 网络扫描器
    "agent":   5,   // 主机 agent
    "adc":     10,  // 权威资产库
}
cfg.MergeRules["os"]       = inventory.StrategyPriority
cfg.MergeRules["hostname"] = inventory.StrategyFirst
cfg.DefaultStrategy        = inventory.StrategyPriority
```

冲突**绝不静默丢弃**：每次裁决都会在资产和全局快照中保留一条 `Conflict`，
包含胜出值、胜出来源、裁决原因（如
`priority: source adc (p=10) outranks agent (p=5)`）以及**全部候选证据**
（来源 + 值 + 时间戳 + 记录 ID），可追溯、可解释。

## 3. 资产关系图

快照内置一张不可变关系图，节点种类：

- `asset` 资产、`service` 服务、`weak_password` 弱口令、
  `vulnerability` 漏洞（CVE）、`domain` 归属域；

边种类：

- 资产 `runs` 服务；
- 服务 `has_weak_password` 弱口令；
- 服务 `has_vulnerability` 漏洞（漏洞节点跨服务共享，可反查影响面）；
- 资产 `belongs_to` 归属域；
- 资产 `depends_on` 资产（依赖按身份键解析，解析不到的引用自动忽略）。

资产更新（合并、改属性）后重建快照时关系图同步重建，边的两端节点必然存在
（测试中逐边校验悬挂引用）。遍历 API：

- `Graph().Neighbors(nodeID, kind, direction)`：邻居查询；
- `Graph().Reachable(nodeID, maxDepth)`：广度优先遍历，**带访问集合，
  环不会导致死循环**（maxDepth<0 表示不限深度）；
- `Graph().Stats()`：按节点/边类型统计。

## 4. 增量变更的幂等应用

- 每条记录以 `RawRecord.ID` 为幂等键：重复摄入同一 ID 直接忽略，不重复
  写 WAL、不产生新版本；
- 增量摄入在内部仍是对**全量变更流**重算快照（`BuildSnapshot` 是纯函数），
  所以乱序、重复、迟到记录的结果与全量重建完全一致；
- 同一批变更重复应用（整批重放、逐条重放）结论不变（有指纹比对测试）。

## 5. 全量重建与增量刷新并存

- `Ingest` / `IngestBatch`：增量提交，记录先**落 WAL（fsync）** 再对
  内存可见，每次提交生成一个新的不可变快照版本并原子替换；
- `Rebuild`：先在锁外对变更流副本做完整重算（期间摄入与查询照常进行），
  提交前再对**当前变更流**重算一次，因此重建期间到达的新变更不会丢失，
  重建完成后清单与关系图与变更流完全对齐；
- 每提交 `SnapshotEvery` 条记录或关闭引擎时落一次快照。

## 6. 并发摄入与查询

- 写路径用互斥锁串行化：多来源并行摄入时同一资产不会被重复创建或互相
  覆盖；
- 读路径**不加锁**：快照通过 `atomic.Pointer` 原子替换，查询永远读到
  单个已提交的完整版本，慢来源（写路径）不会阻塞查询推进；
- 测试覆盖 8 来源并发摄入、摄入途中持续查询、以及慢来源场景下查询不卡死。

## 7. 持久化与中断恢复

数据目录（`DataDir`）下有两类文件：

- `wal.log`：WAL，每条记录为
  `[MAGIC "INV1"][长度][JSON 载荷][CRC32 校验]`，追加写 + fsync；
- `snapshot.json`：快照，写入临时文件 → fsync → 原子 rename → fsync 目录。

恢复流程（`Open`）：

1. 加载最近快照（损坏则忽略，回退到空快照）；
2. 从快照记录的 WAL 偏移之后重放 WAL（按记录 ID 去重，幂等）；
3. 重放时若遇到长度不符、CRC 错误或半截帧，判定为**崩溃残留的 torn
   write**：丢弃该帧及其后续字节，并截断文件尾部——不会出现只写了一半
   的资产或关系；
4. 用恢复后的全量变更流重建快照，保证内存状态自洽。

## 8. 配置项一览

| 配置 | 说明 | 默认值 |
| --- | --- | --- |
| `DataDir` | WAL 与快照目录 | `./inventory-data` |
| `SourcePriority` | 来源优先级映射，高者胜 | 全部 0 |
| `MergeRules` | 按属性名单独指定合并策略 | `hostname=first` |
| `DefaultStrategy` | 未配置属性的默认策略 | `priority` |
| `SnapshotEvery` | 每提交多少条记录自动落快照 | 50 |

## 9. 对外 API 速览

```go
eng, _ := inventory.Open(cfg)
defer eng.Close()

eng.Ingest(record)          // 单条增量（幂等）
eng.IngestBatch(records)    // 批量增量（原子提交为一个版本）
eng.Rebuild()               // 全量重建（与增量并存，不丢变更）

eng.Assets()                // 全部唯一资产
eng.AssetByID(id)
eng.FindByIdentity("web-01") // 按主机名/IP 解析资产
eng.AssetsInDomain("corp.example.com")
eng.ServicesOf(assetID)
eng.VulnerabilitiesOf(serviceNodeID)
eng.WeakPasswordsOf(serviceNodeID)
eng.Conflicts()             // 全部可追溯冲突
eng.Graph()                 // 关系图：Neighbors / Reachable / Stats
eng.Snapshot()              // 当前不可变快照（含版本号与统计）
```
