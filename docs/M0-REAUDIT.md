# ProxyLoom M0 独立三轮复审

> 审计对象：M0 Baseline v0.7 及全部生成文档
>
> 修订产物：M0 Baseline v0.8
>
> 日期：2026-07-17；C-001 证据补充：2026-07-18
>
> 结论：**M1 PASS；C-001 已关闭，无待用户确认项**

## 1. 方法与范围

本次不接受既有 `M0-REVIEW.md` 的 PASS 作为证据，从三个独立失效面重新检查：

1. 需求、版本、术语、构建顺序和协议范围的一致性。
2. 加密轮换、健康批次、队列、关系归属、备份与崩溃恢复的可实现性。
3. OpenAPI、SQLite Schema、协议矩阵和验收场景的机器闭环。

所有确定性 Critical/High/Medium 问题直接修复。只有无法从仓库或公开上游确定、且需要用户指出实际产品身份的信息进入待确认清单。

## 2. 第一轮：范围与跨文档一致性

| ID | 级别 | 发现 | 处理 | 状态 |
| --- | --- | --- | --- | --- |
| M0A-R1-01 | High | 架构先健康过滤再分配名称，首次不健康节点恢复时会重新参与编号，违背稳定名称。 | 名称分配提前到健康过滤前，快照覆盖全部候选并新增 AC-019。 | 已修复 |
| M0A-R1-02 | Medium | Momo Target Profile 在 ADR、矩阵和 API 使用不同 ID，API 创建 Output 又未强制 profile version。 | 统一为 `momo-singbox-1.12`，所有 Profile 显式 `profile_version=1`，Output 必填版本。 | 已修复 |
| M0A-R1-03 | High | 未知 JSON 指纹采用 RFC 8785，可能经 IEEE-754 改写大整数，和无损数字承诺冲突。 | 改为 `opaque-json-v1` 有序 AST，数字保留词法，重复键拒绝，增加 AC-023。 | 已修复 |
| M0A-R1-04 | High | 确定性输出允许“解析库保序则保序，否则排序”两种算法，同一设计可产生不同 Artifact。 | 冻结有序 Raw AST；未修改成员保持原顺序，新增键按 Profile 位置或末尾追加。 | 已修复 |
| M0A-R1-05 | High | 20 项矩阵漏掉 Mihomo v1.19.28 的 6 个真实 parser 类型，并错误把 Naive 归为该版本 Mihomo 类型。 | 从精确 tag/commit 核对，补齐 6 项、修正生态，建立 upstream type assertion；现为 26 项。 | 已修复 |
| M0A-R1-06 | High | ShadowsocksR 在 sing-box v1.12.25 实际是 removed error stub，原矩阵只写“历史/Mihomo”。 | 明确 sing-box raw-only 与目标拒绝语义，Mihomo 原生能力留在 M5。 | 已修复 |
| M0A-R1-07 | Medium | Momo v1.2.1 没有可验证的官方仓库、Release URL 或镜像 digest。 | 锁定官方仓库、Release、commit 与 x86_64/OpenWrt 25.12 资产 SHA-256，Profile 改为 `verified`。 | 已关闭 C-001 |
| M0A-R1-08 | High | Target Profile 机器契约只冻结 Momo wrapper 版本；Momo 实际允许内核独立变化，无法复现目标校验。 | 矩阵、OpenAPI、SQLite 与 Manifest 显式增加 core 及精确版本；Momo 基线冻结为 v1.2.1 + sing-box v1.12.25。 | 已修复 |
| M0A-R1-09 | Medium | Target Profile 的 `exact_version` 在增加 core 后语义含糊，且 SQLite 状态枚举无法保存矩阵/API 的 `p0_baseline` 与 `research_baseline`。 | 版本字段明确为 `client_exact_version` / `core_exact_version`，SQLite 状态枚举与公开契约统一。 | 已修复 |

上游证据：sing-box v1.12.25 tag 对应 commit `73bfb99ebce7923c485435e4faf8571b412065a9`；v1.13.14 对应 `25a600db24f7680ad9806ce5427bd0ab8afe1114`；Mihomo v1.19.28 对应 `cbd11db1e13a75d8e680e0fe7742c95be4cba2be`；Momo v1.2.1 对应 `dc0b315030aff15687829e3c411421299d32298a`，官方 x86_64/OpenWrt 25.12 资产 SHA-256 为 `63646cbe147f4260cdc21fc69176e8f7100ca41a9d79a07b6a4c2f2ff4493394`。Mihomo `adapter/parser.go` 的 21 个代理类型已全部映射到矩阵 canonical ID。

## 3. 第二轮：数据、安全与并发可实现性

| ID | 级别 | 发现 | 处理 | 状态 |
| --- | --- | --- | --- | --- |
| M0A-R2-01 | Critical | 单 wrapping 设计在数据库重包与 `master.key` 替换之间存在崩溃后无法启动的窗口。 | 增加 Master Key Slot、多 wrapping、prepared/active 两阶段、目录原子 rename 与恢复规则；新增 AC-020。 | 已修复 |
| M0A-R2-02 | High | Control probe 被存进 `health_records`，但该表强制绑定节点 Health Key，模型不成立。 | 拆出 `control_probe_records` 和 batch-control 关联；Manifest 固定精确 Control Record。 | 已修复 |
| M0A-R2-03 | High | 原 Schema 只有每批重复的 Batch Item，无法表达“全局 100,000 个唯一 Health Key 队列”。 | 增加全局 `probe_queue_items`、Health Key 唯一约束、租约和数据库硬上限触发器。 | 已修复 |
| M0A-R2-04 | High | 50% 熔断分母包含执行器/目标故障会稀释或放大节点失败率。 | 增加 `eligible_unique`，只统计 success 与 node-attributable failure；新增 AC-021。 | 已修复 |
| M0A-R2-05 | Medium | Source 指针和 Snapshot `current/historical` 双写，允许互相矛盾。 | 删除 Snapshot 状态列，以 `sources.current_snapshot_id` 为唯一权威。 | 已修复 |
| M0A-R2-06 | High | 多个单列外键允许 Snapshot、Artifact、Revision、Queue Item 和 Record 跨所有者/Health Key 串接。 | 关键追溯链改为复合外键，并增加 Revision pointer owner 触发器。 | 已修复 |
| M0A-R2-07 | High | “Master Key 单独备份”与“口令加密备份”没有说明恢复是否还需要原 Key。 | 区分冷复制与自包含托管逻辑备份；托管备份流式重加密、跨实例 staging 恢复，新增 AC-022。 | 已修复 |
| M0A-R2-08 | High | 构建清单没有固定批次和 Control Record，无法重放当时为何暂停批量摘除。 | Manifest 和引用保护增加 Probe Batch/结论/有效样本/Control Record ID。 | 已修复 |
| M0A-R2-09 | Medium | Artifact 状态可从 publishable 任意降级，资源 Revision 指针可跨 owner。 | 增加状态迁移和 owner 校验触发器，发布指针仍只接受同 Output publishable Artifact。 | 已修复 |

## 4. 第三轮：机器契约与验收闭环

| ID | 级别 | 发现 | 处理 | 状态 |
| --- | --- | --- | --- | --- |
| M0A-R3-01 | High | OpenAPI CapabilityDimension 禁止矩阵实际使用的 `evidence/targets/executors/deliveries`，接口无法返回矩阵。 | API schema 与矩阵字段完全对齐，并校验所有 target 引用。 | 已修复 |
| M0A-R3-02 | High | Session CSRF 与一次性发布令牌在响应 schema 中误标 `writeOnly`，且没有重新认证端点。 | 响应秘密改 `readOnly`，增加 5 分钟 reauthenticate、no-store 和 recent-auth 错误。 | 已修复 |
| M0A-R3-03 | High | Restore Preview 把最大 1 GiB 备份塞进 JSON 字符串，且备份/配置导出没有下载契约。 | 改为流式 multipart，增加 staging digest、单次消费与受控下载端点。 | 已修复 |
| M0A-R3-04 | High | API 缺少修订历史、快照 diff、批量检查、名称锁定/压缩、模板刷新、健康容量、审计和设置。 | 补齐 P0 管理路径；危险动作使用 ETag、幂等、预检 digest 或 recent-auth。 | 已修复 |
| M0A-R3-05 | Medium | Health/Probe Policy 有物理表和 Output 引用，却没有创建/发布 API。 | 纳入 Revisioned Resource API 并提供 list/create/publish/history。 | 已修复 |
| M0A-R3-06 | High | 原 AC-001 至 AC-018 不覆盖本次发现的稳定名称、轮换崩溃、全局队列/控制记录、托管恢复与无损数字。 | 新增 AC-019 至 AC-023，Beta 门槛同步更新。 | 已修复 |
| M0A-R3-07 | Medium | 只验证 YAML 可解析会漏掉重复 key，解析器默认会静默覆盖。 | 验证流程增加 Psych AST 重复键检查，并将重复 JSON/YAML key 作为实现安全门槛。 | 已修复 |

## 5. 验证结果

- OpenAPI：65 条 path、81 个 operationId，无重复 operationId；507 个内部 `$ref` 全部解析；无重复 YAML key。
- 协议矩阵：26 个 canonical protocol、每项 6 个能力维度；Mihomo v1.19.28 的 21 个 parser proxy type 全映射；无重复 YAML key和悬空 Target Profile。
- SQLite：65 张表、15 个触发器，可从空库完整执行，`PRAGMA foreign_key_check` 无错误。
- 文档：本地 Markdown 链接全部存在；需求 Beta 门槛已更新到 AC-001 至 AC-023。

## 6. C-001 关闭证据

### C-001 Momo v1.2.1 的权威发布定位：已关闭

2026-07-18 通过公开上游与用户参考设备完成交叉核验：

1. 官方身份为 `nikkinikki-org/OpenWrt-momo`；v1.2.1 Release 发布于 2026-06-03，tag 解析到 commit `dc0b315030aff15687829e3c411421299d32298a`。
2. 官方 x86_64/OpenWrt 25.12 资产下载后 SHA-256 与 GitHub Release digest 一致，资产包含 `luci-app-momo-1.2.1-r1.apk` 与 `momo-2026.06.03-r1.apk`。
3. Momo 是 OpenWrt wrapper，不是独立代理内核：它复制完整 sing-box profile、可应用 UCI mixin、执行 `sing-box format`，按代理模式检查必需 inbound，最后可执行 `sing-box check`。
4. 脱敏实机上安装文件哈希与官方 v1.1.0 tag 完全匹配；APK 数据库记录 sing-box v1.12.15，实际运行的却是定制 v1.13.14。服务 running，配置检查通过。这证明 wrapper/core 必须分别记录，且不能只信包数据库版本。

`source_verification` 已改为 `verified`。M4 仍须用冻结的 v1.2.1 + v1.12.25 组合 fixture 完成真实目标校验，完成前 capability 保持 `not_implemented`。

## 7. 准入结论

本次发现的全部确定性 Critical/High/Medium 问题已进入规范、设计、API、Schema 或验收场景。外部产品身份定位 C-001 已关闭；来源核验与尚未实现的 M4 目标校验保持明确区分。

**ProxyLoom 继续达到 M1 准入水平；当前没有待用户确认的问题。**
