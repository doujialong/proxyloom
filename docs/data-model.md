# ProxyLoom M0 数据模型

> 状态：M0 Baseline
>
> 物理草案：[schema.sql](../db/schema.sql)

## 1. 通用约定

- 所有公开资源使用小写 UUIDv7 字符串，永不复用；发布令牌等秘密另用 256 bit 随机值。
- SQLite 时间使用 UTC Unix 毫秒 `INTEGER`；API 转为带 `Z` 或明确偏移的 RFC 3339。
- 资源更新创建不可变 Revision。资源表只保存当前草稿/已发布 Revision 指针和生命周期状态。
- JSON 配置以 RFC 8785 规范形式计算输入摘要，但敏感 Raw/Canonical 内容摘要使用 HMAC-SHA-256，避免离线猜测。
- 原始内容、节点凭据、请求秘密和 Artifact 使用 AEAD 密文；用于列表查询的协议、状态、计数等安全元数据单独存储。
- 删除默认为归档。被 Artifact 清单、当前发布、审计或保留策略引用的记录不得物理删除。

## 2. 聚合关系

```text
Source 1--* SourceRevision
  |             |
  |             +--* RefreshAttempt
  +--* Snapshot 1--1 RawDocument
          |
          +--* RawNode *--1 Fingerprint
                 |
                 +--* SnapshotOccurrence *--1 NodeOccurrence

Collection --* CollectionRevision --* Source
Pipeline   --* PipelineRevision
Template   --* TemplateRevision --0..1 TemplateSnapshot
Output     --* OutputRevision --> Collection/Pipeline/Template/TargetProfile
  |
  +--* NameAllocation --* NameAllocationSnapshot
  +--* Artifact --1 BuildManifest
  +--1 OutputPublication --> Artifact

EffectiveNode --1 HealthKey --* HealthRecord
ProbeQueueItem --1 HealthKey
ProbeBatch --* ProbeBatchItem --> ProbeQueueItem/HealthRecord
ProbeBatch --* ProbeBatchControl --> ControlProbeRecord
NodeOccurrence --* NodeHealthLink --> HealthRecord
```

`SnapshotOccurrence` 是 Snapshot 中一次实际出现与长期 `NodeOccurrence` 的连接表。这样同一 Raw Node 重复出现时不会被关系模型误合并。Snapshot 是否为当前版本只由 Source 的 `current_snapshot_id` 指针派生，不在 Snapshot 再保存第二份 `current/historical` 状态。

## 3. 来源与快照

### Source / SourceRevision

Source 是稳定身份。Revision 保存来源类型、加密 URL/正文引用、请求策略、SSRF 私网授权、刷新计划、内容门槛和用途。只有 `published_revision_id` 用于自动刷新；草稿可预览。

### RefreshAttempt

每次拉取均不可变记录阶段、HTTP 元数据、解析计数、失败分类和脱敏错误。`accepted_snapshot_id` 可为空；失败不覆盖 Source 的 `current_snapshot_id`。

### Snapshot / RawDocument

Snapshot 只代表通过有效性门槛的内容。RawDocument 保存加密原文 Blob、检测格式、内容 HMAC、响应元数据和解析限制版本。`304 Not Modified` 的 Attempt 可指向已有 Snapshot，不新建伪快照。

### RawNode / CanonicalNode

RawNode 包含：格式 ID、格式适配器版本、原值类型、加密 Blob、JSON Pointer/行槽位、原始显示名密文、协议 ID 或未知类型、解析警告。CanonicalNode 是一对一、可重新生成的版本化密文视图；`completeness` 为 `complete|partial|opaque`。

Raw Node 本身不跨 Snapshot 复用，避免改变历史。相同内容通过 Fingerprint 和 NodeOccurrence 关联。

## 4. 身份与出现记录

### Fingerprint

Fingerprint 摘要由独立 HMAC Key 生成，记录 `kind=semantic|opaque_structural`、算法、投影版本与 Key ID。数据库唯一约束只减少重复存储，不能驱动自动删节点。

### NodeOccurrence

NodeOccurrence 的范围是单个 Source，状态为 `present|absent|retired`，保存首次/末次出现、缺席起点和关联算法版本。它是名称与节点历史的主体，不等于连接 Fingerprint。

关联结果写入 SnapshotOccurrence，包含 `match_method=fingerprint_unique|path|duplicate_slot|auxiliary_unique|new|ambiguous_new` 和确定性 occurrence ordinal。歧义必须可查询。

## 5. 处理、目标与补丁

CollectionRevision 通过有序成员表引用 Source/手工节点。PipelineRevision 保存有序、带 schema 版本的操作。每次操作输出 Patch：

```json
{
  "op": "replace",
  "path": "/tag",
  "value": "香港 01 #2",
  "origin": "name-conflict",
  "operation_revision_id": "..."
}
```

Patch 只允许 `add|remove|replace`，不允许依赖数组当前位置的隐式文本替换。连接 Patch 应用后形成构建期 EffectiveNode；数据库只保存其加密投影、Health Key 和构建追踪，不把它变成新的 Raw Node。

TargetProfile 是版本化注册数据，固定格式族、客户端、内核、精确版本、能力/验证器版本。M0 基线见 ADR-0005。

## 6. 名称分配

NameAllocation 的唯一范围是 Output：`(output_id, node_occurrence_id)`。记录基础名、最终名、后缀号、锁定状态、allocation version、last_seen_at 和 `reserved_until`。

在一个 Output 内：

- 最终名唯一；suffix `1` 表示无后缀，`n >= 2` 输出 ` #n`。
- 缺席后保留 30 天，期间名称和后缀仍占用。
- 新节点从当前可用的最小 suffix 开始，但不得改变已有分配。
- 手工压缩产生 Output 新 Revision 和新的分配版本，不原地改写历史 Snapshot。

每次构建在健康过滤前复制全部候选映射到不可变 NameAllocationSnapshot/Item。Item 保存 `candidate_ordinal` 和可空 `included_ordinal`；被过滤节点仍在 Snapshot 中占用名称。Artifact 只引用 Snapshot，重放不读取当前分配。

## 7. 健康数据

HealthKey 是 Effective Node 的连接投影、执行器及版本、Probe Profile Revision、Network Context Version 的 HMAC。显示名称、来源别名和 Output 名称不进入投影。

HealthRecord 是一次不可变物理探测结果，保存层级、目标、阶段耗时、分类、成功与否、执行器版本和脱敏诊断。NodeHealthLink 把一个 Record 关联到多个 NodeOccurrence，保留每个节点独立状态转换原因。

全局 ProbeQueueItem 以 Health Key 唯一化活动物理探测并持有优先级、到期时间和租约；ProbeBatchItem 只把一个 Output 批次关联到 Queue Item 和完成后的 HealthRecord。ControlProbeRecord 不绑定节点 Health Key，通过 ProbeBatchControl 关联一个或多个相同网络上下文批次。Batch 关闭后不再接收新 Item。

批次结论为 `normal|mass_failure_suppressed|control_failure_suppressed|insufficient_sample`。`eligible_unique` 只统计 success 与 node-attributable failure；执行器、目标、资源错误、取消和不支持不进入 10 个样本或失败率分母。

节点当前状态是可重建缓存，来源于最新未陈旧 Record、连续成功/失败计数和策略 Revision。Artifact 清单引用确切 Record，不引用这个可变缓存。

## 8. 构建、发布与任务

Artifact 状态为 `building|validated|rejected|publishable`。内容 Blob、BuildManifest、验证结果和 diff 在事务中固定。`output_publications` 是 Output 唯一当前指针，包含模式 `automatic|manual_lock`、自动构建序号和切换时间。

Job 保存类型、优先级、去重键、输入摘要、租约、attempt、进度和脱敏错误。任务正文含秘密时保存加密 payload Blob。`idempotency_records` 保存主体、作用域、键 HMAC、请求摘要和响应/Job ID，默认 24 小时清理。

## 9. 加密与 Blob

`data_keys` 保存 DEK/HMAC Key 的身份与用途，不内联单一 Master wrapping；`master_key_slots` 记录非秘密 Master Key ID 与 `prepared|active|retired` 状态，`master_key_wrappings` 允许同一 Data Key 在轮换期间同时由旧、新 Master Key 包装。`encrypted_blobs` 保存 kind、Data Key ID、nonce、AAD 版本、ciphertext 路径或内联数据和大小。Blob 明文摘要按敏感性使用 HMAC；公开 Artifact 可另存 SHA-256 作为 ETag。

托管备份是自包含的加密逻辑导出：应用密文只在内存中解密并立即流式写入独立备份 AEAD 容器。Restore Preview 解密并校验后，把可恢复内容重新加密为有过期时间的 staging Blob；正式 Restore 只消费未过期且 digest 匹配的 staging 记录。直接冷复制数据目录不是托管备份，仍依赖单独保存的原 Master Key。

删除业务记录时先标记 Blob 不再引用；清理任务在两个保留周期后再次确认引用计数为零才删除文件。备份以 SQLite 在线备份点和 Blob 清单形成一致性集合。

## 10. 强制不变量

1. 一个 Source 只能指向通过门槛的当前 Snapshot。
2. RawNode 的原始密文创建后不可修改。
3. Fingerprint 相同不能导致 SnapshotOccurrence 数量减少。
4. 一个 Output 的活动/保留 NameAllocation 最终名不得冲突。
5. Artifact 必须同时拥有清单、内容、验证结果和输入摘要才能 publishable。
6. OutputPublication 只能指向同一 Output 的 publishable Artifact。
7. Health Record 不可更新；更正必须新增记录。
8. 被当前发布或清单引用的 Snapshot、Name Allocation Snapshot、Health Record 和 Artifact 不得清理。
9. AEAD 验证失败不能转换为空值或默认值。
10. 所有 Revision 引用在 Job 开始后固定，运行中编辑只影响后续 Job。

## 11. 状态迁移

```text
Resource: active -> archived -> deleted (仅满足引用与保留条件)
Revision: draft -> published -> superseded -> archived
Snapshot: accepted -> current/historical（由 Source 指针派生） -> retained/deleted
Occurrence: present <-> absent -> retired
Artifact: building -> validated -> publishable
                    \-> rejected
Job: queued -> leased -> running -> succeeded
                         |       \-> failed -> queued (重试)
                         +--------> cancelled/dead
```

健康状态机详见 [health-check.md](./health-check.md)。
