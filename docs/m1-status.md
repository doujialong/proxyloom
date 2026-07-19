# ProxyLoom M1 实现状态

> 状态：M1 Exit PASS
>
> 日期：2026-07-18
>
> 入口基线：[m0-checklist.md](./m0-checklist.md)
>
> 出口审计：[M1-EXIT-AUDIT.md](./M1-EXIT-AUDIT.md)

## 1. 当前结论

M1 定义的不联网无损内核纵向链路已经完成并通过出口审计：sing-box Raw Document -> 有序 Raw Node -> Canonical 派生视图 -> 版本化 Fingerprint 投影 -> Node Occurrence -> Name Allocation -> 最小 `tag` Patch -> 确定性 `outbounds` Artifact。

sing-box 是首个证据适配器，不是产品范围上限。协议注册表已经按 `(format_id, raw_type)` 隔离映射，HMAC、Occurrence 和命名核心不依赖 sing-box 私有字段；URI、Mihomo 和其他客户端格式必须按[适配器契约](./adapter-contract.md)继续接入并独立升级能力矩阵。

M1 PASS 不代表 ProxyLoom 已成为可运行服务，也不代表所有协议的六项能力已经完成。SQLite、HTTP/API、加密 Blob、调度器、真实健康检查、跨格式渲染、目标内核验证和容器属于后续里程碑。

## 2. 已实现模块

| 模块 | 版本 | 当前能力 |
| --- | --- | --- |
| `internal/jsonlossless` | `ordered-json-v1` | 严格 JSON、重复键拒绝、无配对 surrogate 拒绝、对象顺序和数字词法保留、默认限制及不可突破的全局硬上限 |
| `internal/format/singbox` | `sing-box-json-v2` | 完整配置、出站数组、单节点对象；14 个 v1.12 代理类型、SSR raw-only、逻辑出站和未知类型分类 |
| `internal/protocol` | `protocol-registry-v3` / `singbox-canonical-v2` | 格式感知注册；九个 M1 协议的核心认证、TLS、ECH、uTLS、Reality、传输、Multiplex 和协议字段派生视图 |
| `internal/identity` | `singbox-connection-v2` / `opaque-json-v1` | 格式无关投影接口与独立 256 bit Key 的 HMAC-SHA-256；已登记字段使用语义投影，未适配协议使用不透明结构投影 |
| `internal/occurrence` | `occurrence-v1` | 唯一指纹、路径、duplicate slot、唯一辅助证据、歧义新建、30 天恢复/退休，索引化近线性处理 |
| `internal/naming` | `name-suffix-v2` | Output 范围稳定 ` #2` 后缀、保留期、基础名保护、最小空号、逻辑出站避让与锁定冲突 |
| `internal/patch` | `singbox-tag-patch-v1` | 深拷贝 Raw Node，只允许新增/替换顶层 `/tag` |
| `internal/build` | `singbox-outbounds-v2` | 健康式过滤前分配名称、无名节点稳定命名、不可变分配快照、固定格式 Artifact |

Canonical View 当前是可查询的类型化子集，因此逐节点 `Completeness` 和能力矩阵 `normalize` 均保持 `partial`。完整 Raw Node 和已声明的连接身份投影不受此限制，但不得据此宣称已经具备跨格式转换。

## 3. 验收证据

| 场景 | 结果 | 自动化证据 |
| --- | --- | --- |
| AC-001 未知字段无损 | PASS（M1） | `TestM1GoldenOutbounds`、`TestM1ProtocolFixturesPassThroughLosslessly` |
| AC-002 只改节点名称 | PASS（M1） | `TestApplyTagChangesOnlyTag`、golden diff 仅 `/tag` |
| AC-003 稳定保留重复节点 | PASS（M1） | `TestAllocateStableSuffixLifecycle`、`TestReconcileDuplicateLifecycle` |
| AC-009 未知协议不中断 | PASS（M1） | `TestUnknownProtocolPassesThroughWithoutSemanticConversion` |
| AC-015 数字后缀生命周期 | PASS（M1 算法范围） | `TestAllocateReusesSmallestSuffixAfterRetention` |
| AC-019 过滤不改变名称 | PASS（M1 算法范围） | `TestNamingOccursBeforeHealthStyleExclusion` |
| AC-023 重复键与无损数字 | PASS（M1） | duplicate-key、large integer、exponent、trailing-zero 与 fuzz tests |
| RAW-001 单节点对象 | PASS（M1） | `TestParseSingleNodeObject`、`TestNodeWithoutTagGetsStableProtocolName` |
| PIPE-004 语义身份投影 | PASS（M1） | 九协议 identity fixture 与连接字段变形测试 |

脱敏 fixture 位于 `internal/build/testdata/` 和 `internal/protocol/testdata/`，不包含真实节点、订阅 URL 或生产秘密。

## 4. 质量与容量

2026-07-18 本地验证环境：Apple M1、8 GiB、macOS 26.5.2、Go 1.18.1、`darwin/arm64`。

- `go vet ./...`、`go test ./...`、`go test -race ./...`：PASS。
- 核心包连续重放 `-count=10`：PASS。
- 总语句覆盖率：82.6%。
- 10 秒持续 fuzz 烟雾任务已进入 CI；本地运行超过 11 万次输入，无崩溃。
- 20,000 节点解析：192.1 ms，198.4 MB 累计分配。
- 20,000 节点 Occurrence：首次 45.5 ms、稳态 39.2 ms、全部连接变化辅助匹配 65.0 ms。
- 20,000 个完全同名节点分配：57.1 ms。
- 同一输入和固定分配重放：Artifact 逐字节一致。
- 实现不读取隐式系统时间、随机数、环境变量或网络；时间、HMAC Key 和 ID 生成器均由调用方注入。

以上是开发机基准，不替代正式版要求的 2 vCPU、2 GiB、Linux 容器参考设备报告。

## 5. 后续边界

M2 可以开始后台服务、SQLite migration、加密 Blob、API 和容器的实现。首个 migration 仍必须从空库构建并验证备份回滚，不能把 M0 的 `db/schema.sql` 直接当作已发布迁移。

协议与格式扩展继续按能力矩阵推进：URI/Base64、Mihomo YAML/JSON 和客户端专有格式尚未实现；跨格式编辑、真实协议健康检查和目标内核校验也保持 `not_implemented|blocked`。这些是产品“全面支持”的持续交付内容，不允许通过 sing-box 首个切片推导为已支持。

当前没有需要用户单独确认的 M1 出口问题。
