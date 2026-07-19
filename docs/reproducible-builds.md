# ProxyLoom M0 可复现构建设计

> 状态：M0 Baseline
>
> 对应需求：BUILD-004 至 BUILD-008

## 1. 可复现边界

同一 Build Manifest、同一目标平台与同一已固定工具资产必须生成逐字节相同 Artifact。M0 不承诺 amd64 与 arm64 上外部验证器输出日志逐字节相同，但最终 JSON Artifact 必须由 ProxyLoom 自身确定性编码；清单记录平台以便定位差异。

历史回滚直接切换已保存 Artifact，不用当前来源、名称或健康状态重算。

## 2. Manifest v1

Manifest 是 RFC 8785 规范 JSON，顶层字段如下：

```json
{
  "schema_version": 1,
  "artifact_id": "UUIDv7",
  "output_id": "UUIDv7",
  "output_revision_id": "UUIDv7",
  "build_sequence": 42,
  "reason": "source_snapshot_accepted",
  "resource_revisions": {
    "collection": "UUIDv7",
    "pipeline": "UUIDv7",
    "template": "UUIDv7-or-null",
    "health_policy": "UUIDv7",
    "probe_profile": "UUIDv7"
  },
  "source_snapshots": [
    {"source_id": "UUIDv7", "snapshot_id": "UUIDv7", "content_hmac": "base64url"}
  ],
  "target_profile": {
    "id": "singbox-1.12",
    "profile_version": 1,
    "client": {"id": "sing-box", "version": "v1.12.25"},
    "core": {"id": "sing-box", "version": "v1.12.25"},
    "adapter_version": "semver",
    "validator_version": "semver"
  },
  "registries": {
    "format": "semver",
    "protocol": "semver",
    "occurrence_algorithm": "occurrence-v1",
    "name_algorithm": "name-suffix-v2",
    "sort_algorithm": "stable-sort-v1"
  },
  "name_allocation_snapshot_id": "UUIDv7",
  "health_inputs": [
    {"node_occurrence_id": "UUIDv7", "health_record_id": "UUIDv7", "state": "healthy", "stale": false}
  ],
  "health_batches": [
    {"batch_id": "UUIDv7", "conclusion": "normal", "control_record_ids": ["UUIDv7"], "eligible_unique": 20, "node_failure_unique": 1}
  ],
  "dynamic_inputs": {"generated_at": "2026-07-17T00:00:00Z"},
  "service": {"version": "semver+commit", "go": "exact", "platform": "linux/amd64"},
  "input_digest": "sha256-base64url"
}
```

数组排序是协议的一部分：Source 按 Collection member ordinal 后以 ID 兜底；health inputs 按 Node Occurrence ID；名称项先按 candidate ordinal，已包含项另记录 included ordinal。Manifest 不允许 map 的运行时遍历顺序影响编码。

## 3. 固定输入过程

构建 Job 领租约后在一个只读快照事务中：

1. 读取 Job 已固定的 Output Revision，拒绝草稿或已归档输入。
2. 解析它引用的 Collection/Pipeline/Template/Policy Revision。
3. 为每个 Source 固定已接受 Snapshot；无有效 Snapshot 则按 Output 门槛失败。
4. 固定 Target Profile、注册表与适配器资产版本。
5. 选择 `observed_at <= build_health_cutoff` 的精确 Health Record，并保存 ID；同时固定对应 Output Probe Batch 的结论、有效样本计数和全部 Control Probe Record ID，不只保存截止时间或可变当前状态。
6. 在任何健康过滤前，为全部候选 Occurrence 基于当前分配创建不可变 Name Allocation Snapshot；Snapshot 同时记录候选顺序和可空的最终输出顺序。
7. 生成 Manifest 输入摘要；后续阶段只能按清单读取。

若名称分配需要新增，分配事务先比较 Output allocation version。并发构建冲突时较晚事务重新固定清单，不能各自发布不同分配。

## 4. 确定性转换规则

- JSON 输入保存原值；输出统一 UTF-8、LF、两空格缩进、无 BOM、末尾一个换行。
- Raw JSON 使用保留对象成员顺序和数字词法的有序 AST；未修改对象成员保持输入相对顺序。新增键置于 Target Profile 声明位置，没有声明时追加到对象末尾。实现不得退化为无序 map 后再选择另一套排序规则。
- 接受为结构化配置的 JSON 不允许重复对象键；失败路径保存原始密文和稳定错误，但不得用“第一个或最后一个值获胜”生成 Artifact。
- 数值不经过浮点运算；Raw JSON number 保存词法值，未修改时原值输出，修改值使用十进制定点/整数规范编码。
- 数组保持输入顺序，只有显式排序操作可以改变；排序必须稳定并以 Node Occurrence ID 作为最终兜底。
- 正则引擎、Unicode normalization、地区表和模板函数均固定版本与 locale；默认不做 Unicode normalization。
- 当前时间、随机值、主机名和环境变量不能隐式读取。需要的生成时间等作为 `dynamic_inputs` 固定。
- 自动名称冲突只产生 `/tag` 或目标显示字段 Patch，不重建对象。

## 5. 验证与 Artifact 状态

验证分三级并写清强度：

1. `structural`：JSON 解析、类型、名称唯一、引用完整。
2. `semantic_internal`：协议必需字段与 Target Profile 规则。
3. `target_binary`：固定摘要的真实客户端/内核检查；P1 承诺，P0 Profile 若具备稳定工具可提前使用。

任一级失败产生 rejected Artifact 记录和脱敏诊断，但不能切换发布指针。验证器版本与资产 SHA-256 进入清单。外部工具生成的时间戳或绝对路径只进入诊断，不进入 Artifact。

## 6. 原子发布与旧任务保护

每个 Output 单调递增 `build_sequence`。Artifact 完成后事务执行：

```text
if publication.mode == automatic
and artifact.output_revision_id == output.published_revision_id
and artifact.build_sequence >= publication.automatic_sequence
then switch current_artifact_id and automatic_sequence
else retain artifact without publishing
```

手工回滚把模式设为 `manual_lock` 并指向历史 Artifact。自动构建仍可生成但不切换，直到用户明确退出锁定。Artifact 内容先完整写入、验证摘要，再提交数据库指针，发布端永远看不到部分文件。

## 7. 重放

`proxyloom build replay <artifact-id>` 读取原 Manifest，在隔离工作目录重建，不创建新名称分配或选择新健康记录。重放结果计算 SHA-256 与原 Artifact 比较：

- 一致：记录 replay success。
- 不一致：保留两者摘要、首个结构化差异路径、平台与工具版本，返回 `build_not_reproducible`。
- 输入已按策略清理：清理本应被引用保护，视为数据完整性错误而不是悄悄使用当前输入。

## 8. 保留与清理

当前 Artifact、手工锁定 Artifact、默认最近 30 个 Artifact 及其直接输入都受引用保护。Manifest 引用的 Snapshot、Raw Blob、Revision、Name Allocation Snapshot、Health Record、Probe Batch、Control Probe Record、Target Profile 和 Adapter 资产不得先清理。清理采用 mark-and-sweep，两次扫描间隔至少一个任务租约上限。

## 9. 测试策略

- golden：未知嵌套字段、null、数字词法值、重复节点、最小 Patch。
- metamorphic：交换来源输入顺序不改变已分配名称；无关字段不改变 Fingerprint；连接字段改变 Health Key。
- concurrency：旧构建晚完成、名称分配竞争、回滚期间自动构建。
- replay：同平台连续两次逐字节一致；清单缺一项时验证失败。
- fault injection：Blob 写一半、SQLite commit 失败、验证器崩溃、磁盘满，当前发布始终可读。
