# ProxyLoom M0 三轮设计终审

> 历史记录：本结论已由 [M0-REAUDIT.md](./M0-REAUDIT.md) 的 v0.8 独立复审取代。
>
> 审计对象：M0 Baseline v0.7 及全部技术设计产物
>
> 日期：2026-07-17
>
> 最终结论：**PASS，达到 M1 准入水平**

## 1. 审计方法

本次按三种不同失效面复核，不把“文档存在”当作设计完成：

1. 范围、版本、术语与需求一致性。
2. 数据、安全、并发、容量与失败恢复可实现性。
3. API/Schema/协议矩阵的机器契约和 M1 可执行性。

Critical/High 问题必须在 M0 关闭；Medium 必须修复或明确证明不阻塞。Low 可以进入后续阶段清单。

## 2. 第一轮：范围与一致性

| ID | 级别 | 发现 | 处理 | 状态 |
| --- | --- | --- | --- | --- |
| M0-R1-01 | High | D-009 只写 `1.12.x`，历史构建和验证器无法锁定精确版本。 | 固定 Momo v1.2.1、sing-box v1.12.25；v1.13.14 作为首个兼容目标。 | 已修复 |
| M0-R1-02 | High | 20,000 节点、30 分钟周期与“最多 16 并发”在平均探测超过 1.44 秒时不可同时满足。 | D-019 改为默认 16、受保护上限 64；加入容量公式、估算、陈旧和告警语义。 | 已修复 |
| M0-R1-03 | High | “同批 50%”没有批次边界，可能把不同 Output/时间窗口混合熔断。 | 固定 Output + Policy + Probe Profile + Executor + Network Context + 5 分钟窗口。 | 已修复 |
| M0-R1-04 | High | 构建清单只有健康截止时间，无法重放当时实际采用的状态。 | 清单固定 Name Allocation Snapshot 与每个精确 Health Record ID/结果。 | 已修复 |
| M0-R1-05 | Medium | 协议清单可能被误读为已经实现“全协议支持”。 | 矩阵顶层声明 `design_only/not_started`，每个六维状态独立为 `not_implemented`/blocked。 | 已修复 |

第一轮没有剩余范围冲突。长期“全协议”被定义为可审计演进义务，不是首版虚假完成声明。

## 3. 第二轮：实现、安全与恢复

| ID | 级别 | 发现 | 处理 | 状态 |
| --- | --- | --- | --- | --- |
| M0-R2-01 | High | 未知协议没有语义字段，普通 Fingerprint 无法安全定义。 | 使用排除格式级显示字段后的 RFC 8785 对象 HMAC，并标记 `opaque_structural`，禁止语义去重结论。 | 已修复 |
| M0-R2-02 | High | 同一来源中完全相同的多个节点无法靠 Fingerprint 区分。 | 定义 duplicate slot、路径/旧 ID 配对、数量减少保留最早槽位和歧义新建规则。 | 已修复 |
| M0-R2-03 | High | `master.key` 只有 `0600`，非 root 容器的实际属主未定义。 | 固定运行 UID/GID `65532:65532`，初始化、格式、只读路径和安全失败顺序均已定义。 | 已修复 |
| M0-R2-04 | Critical | “首次启动创建管理员”允许同网段攻击者抢先占有空实例。 | 增加本机生成的 256 bit Setup Token，HMAC 存储、一次使用；M0 初始有效期为 30 分钟，后续可用性回归调整为默认 24 小时。 | 已修复 |
| M0-R2-05 | High | 外部探测进程会接触秘密，若 argv/tmp/端口不受限会扩大泄漏面。 | 固定 pipe 协议、stdin/0600 tmpfs、loopback 随机端口、进程组与资源限制。 | 已修复 |
| M0-R2-06 | Medium | Schema 曾用占位迁移 checksum，会制造已经校验的假象。 | 删除假 checksum；草案只写 metadata，实际 migration 由 runner 计算 SHA-256。 | 已修复 |
| M0-R2-07 | Medium | Target Profile 主键不能保留同一 ID 的多个不可变 profile 版本。 | 改为 `(id, profile_version)` 复合主键，Output Revision 固定两列。 | 已修复 |

第二轮没有未处理 Critical/High。密码/AEAD 参数、SSRF、备份、错误 Key、最后有效 Artifact 和执行器失败隔离均有明确设计与验收路径。

## 4. 第三轮：机器契约与交付

| ID | 级别 | 发现 | 处理 | 状态 |
| --- | --- | --- | --- | --- |
| M0-R3-01 | High | 初版 OpenAPI 未覆盖 Collection/Pipeline/Template/Output 的 Revision 发布动作。 | 增加带 `If-Match` 的发布/归档契约。 | 已修复 |
| M0-R3-02 | High | API-003 要求的配置导入预检，以及备份/恢复预检没有接口。 | 增加 config export/import preview/import 与 backup/restore preview/restore 异步端点。 | 已修复 |
| M0-R3-03 | Medium | OpenAPI 协议能力结构与 YAML 矩阵的 `capability` 层级不同。 | 调整 API schema 与机器矩阵一致。 | 已修复 |
| M0-R3-04 | Medium | SourceInput 未约束 remote 必须有 URL、inline/upload 必须有 content。 | 改为 OpenAPI 3.1 `oneOf` 判别结构。 | 已修复 |
| M0-R3-05 | Medium | 只有通用 ErrorResponse，没有稳定 code 注册表。 | 增加 API v1 约定和 P0 稳定错误码表。 | 已修复 |
| M0-R3-06 | Medium | 仓库入口声明 AGPL，但缺少标准许可证正文。 | 加入 GNU AGPL v3 官方完整文本，以 `or later` 方式声明。 | 已修复 |

机械验证结果：

- `openapi.yaml` 可由 YAML 解析器加载，42 条 path、55 个 operationId 无重复，359 个内部 `$ref` 全部解析。
- `protocol-matrix.yaml` 可加载，20 个协议条目均具备六个能力维度；D-010 的 7 个真实探测协议都指向 M3。
- `schema.sql` 可在空 SQLite 数据库完整执行，创建 56 张表，`PRAGMA foreign_key_check` 无错误。
- M0 Markdown 本地链接全部可解析；`LICENSE` 是完整 GNU AGPL v3 正文。

## 5. 剩余风险

| 风险 | 当前处置 | 阻塞阶段 |
| --- | --- | --- |
| Momo/sing-box 实际字段兼容仍需 fixture 证明 | M1/M4 锁定脱敏 fixture 与目标二进制 | 不阻塞 M1；阻塞 Beta |
| 外部二进制资产摘要和组合分发义务尚未产生 | 引入二进制时锁 SHA-256、SBOM、许可证与源码地址 | 不阻塞 M1；阻塞对应镜像 |
| 20,000 节点实际耗时依赖网络/NAS | M3 基准并校准容量估算，永不突破资源硬上限 | 不阻塞 M1；阻塞 Beta |
| 20 项初始协议清单无法覆盖未来/私有协议 | unknown 保留 + 每次稳定版差异更新 + blocked 状态 | 持续义务 |
| GitHub 组织和名称商标未做发布时终检 | 外部创建留到用户授权的发布准备阶段 | 不阻塞 M1；阻塞公开发布 |

这些风险都有责任阶段和失败行为，不需要在 M0 假设性解决。

## 6. 准入结论

M0 的规范、架构、数据、安全、健康、构建、API、Schema 和协议矩阵已经互相闭合；所有发现的确定性 Critical/High/Medium 问题均已处理。当前没有悬而未决的用户选择，也没有需要用实现试错来决定的架构核心。

**ProxyLoom 达到 M0 设计完成门槛，可以进入 M1。** M1 必须按 checklist 的无损纵向切片推进，并以 golden tests 证明设计，不得把矩阵中的计划状态提前改成“已支持”。
