# ProxyLoom M1 三轮出口审计

> 审计对象：M1 无损内核实现、测试、CI、能力矩阵与阶段文档
>
> 日期：2026-07-18
>
> 结论：M1 Exit PASS；确定性问题已修复；无待用户确认项

## 1. 审计方法

三轮分别检查：核心正确性与需求契约；资源、安全和确定性；扩展边界、能力声明和阶段准入。Critical/High 会阻塞出口，Medium 必须修复或有明确阶段归属，Low 不得形成虚假能力声明。

## 2. 第一轮：正确性与无损契约

| ID | 级别 | 发现 | 处理 | 状态 |
| --- | --- | --- | --- | --- |
| M1-R1-01 | High | 已登记协议标记为 `semantic`，实际仍对删除 `tag` 后的整棵 Raw JSON 求摘要，无关字段会改变身份。 | 增加九协议 `singbox-connection-v2` 声明字段投影；未适配协议降为 `opaque_structural`；补身份正反变形测试。 | 已修复 |
| M1-R1-02 | High | RAW-001 要求单节点 JSON，解析器却把所有根对象当成完整配置。 | 增加 `single_node` 文档形态、根 JSON Pointer 和往返测试。 | 已修复 |
| M1-R1-03 | High | `Node` 自动生成的 `Node #2` 可抢占另一个节点的原始基础名 `Node #2`。 | `name-suffix-v2` 预先保护全部候选基础名，生成后缀时跳过。 | 已修复 |
| M1-R1-04 | Medium | 新增逻辑出站保留名时，未锁定的历史名称也直接报冲突。 | 未锁定分配确定性迁移到下一可用名称；锁定冲突仍明确失败。 | 已修复 |
| M1-R1-05 | Medium | 合法但无 `tag` 的节点无法构建。 | 使用原始协议类型生成稳定基础名，并记录 `name-required` 最小 Patch。 | 已修复 |
| M1-R1-06 | Medium | Canonical 子集被标记为 `complete`，可能被误解为可全面转换。 | 保持 `partial`，Raw 无损、身份投影和跨格式能力分别陈述。 | 已修复 |

## 3. 第二轮：资源、安全与确定性

| ID | 级别 | 发现 | 处理 | 状态 |
| --- | --- | --- | --- | --- |
| M1-R2-01 | High | 20,000 节点首次 Occurrence 关联约 23 秒、2 亿次分配，存在二次扫描。 | 建立指纹/辅助证据索引和计数式 duplicate slot 分配器；三类 20k 场景降至 39-65 ms。 | 已修复 |
| M1-R2-02 | High | 全部同名节点分配会从 1 反复扫描后缀，最坏 O(n²)。 | 为每个基础名维护最小可用后缀游标；20k 同名约 57 ms。 | 已修复 |
| M1-R2-03 | High | 调用方可以提高 JSON 限制并突破安全文档冻结的全局硬上限。 | 解析器内部封顶 50 MiB、深度 128、单字符串 4 MiB、500 万 AST 值；来源只能收紧。 | 已修复 |
| M1-R2-04 | Medium | 只有 fuzz seed 单测，没有持续随机烟雾门禁。 | CI 增加稳定版 Go 的 10 秒 `FuzzParseRoundTrip` 独立作业；本地验证通过。 | 已修复 |
| M1-R2-05 | Medium | Fingerprint Key 接受任意大于 32 字节的输入，与冻结的 256 bit 用途 Key 不一致。 | 强制恰好 32 字节并保持调用方注入。 | 已修复 |

## 4. 第三轮：通用性与能力声明

| ID | 级别 | 发现 | 处理 | 状态 |
| --- | --- | --- | --- | --- |
| M1-R3-01 | High | Identity 实现直接导入 sing-box 协议注册，妨碍 URI/Mihomo 复用核心。 | Identity 改为通用 Projection 输入，格式适配层负责字段选择。 | 已修复 |
| M1-R3-02 | High | 协议注册只按 `rawType` 查找，不同格式的同名类型会碰撞。 | 注册键改为 `(format_id, raw_type)`，开放受校验的格式专属注册并增加隔离测试。 | 已修复 |
| M1-R3-03 | High | 能力矩阵仍把已有代码全部记为未实现，也可能诱发一次性升级过度。 | 九协议三个维度仅升为跨格式 `partial`；未知 sing-box 协议的识别/无损升为 `implemented`；转换、健康和目标校验不动。 | 已修复 |
| M1-R3-04 | Medium | 算法行为变化后版本号仍为 v1，未来持久化记录无法区分。 | 提升 Registry、Format、Snapshot、Identity、Naming 和 Builder 的对应版本。 | 已修复 |
| M1-R3-05 | Medium | 缺少可执行的多格式扩展边界。 | 新增[适配器契约](./adapter-contract.md)，冻结格式、协议、目标和执行器四层职责与准入证据。 | 已修复 |

## 5. 出口门槛

| 门槛 | 结果 | 证据 |
| --- | --- | --- |
| 严格有界 Raw AST 与同格式无损 | PASS | JSON 单测、九协议往返、unknown golden、fuzz |
| 稳定身份、重复保留与命名 | PASS | identity metamorphic、Occurrence 生命周期、Name Allocation 生命周期 |
| 确定性最小 Patch 与 Artifact | PASS | golden、重放、`-count=10`、race |
| 20,000 节点参考容量 | PASS（开发机） | 三包 benchmark；正式参考机报告后续补齐 |
| 通用适配边界 | PASS | 格式感知注册、通用 Identity Projection、适配器契约 |
| 六维能力声明无夸大 | PASS | `protocol-matrix.yaml` 0.3.0-m1 |
| 静态、单测、竞态和文档契约 | PASS | `go vet`、`go test`、`go test -race`、结构化文档检查 |

## 6. 准入结论

M1 的离线无损内核和首个 sing-box 参考适配器达到出口水平，M2 可以开始。当前没有 Critical、High 或未处置 Medium，也没有需要用户确认的行为决策。

URI/Base64、Mihomo YAML/JSON、其他客户端格式、跨格式渲染、真实健康检查和目标二进制校验均未实现，并已在能力矩阵中保持诚实状态。它们属于“全面协议与格式支持”的后续持续交付范围，不能从本次 M1 PASS 推导为已支持。
