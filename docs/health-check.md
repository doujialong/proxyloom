# ProxyLoom M0 健康检查与容量设计

> 状态：M0 Baseline
>
> 对应需求：HEALTH-000 至 HEALTH-008

## 1. 两个独立健康域

Source Health 只描述获取和解析订阅的能力；Node Health 描述通过 Effective Node 访问探测目标的能力。来源失败时继续使用最后有效 Snapshot，节点失败时只由已确认 Output 策略决定是否过滤，两者不得相互覆盖。

`stale` 是附加布尔属性。Source Snapshot 默认 72 小时陈旧，Node 结果默认 1 小时陈旧。

## 2. 探测层级与结果分类

| 层级 | 证明内容 | 不证明内容 |
| --- | --- | --- |
| endpoint | DNS 与适用的 TCP/UDP 建连 | 认证、TLS、代理转发可用 |
| proxy_http | 真实协议栈经代理访问 HTTPS 目标 | 任意业务站点、UDP、流媒体可用 |
| capability | P1 的 DNS/UDP/业务目标 | 未被测试的其他能力 |

结果类别：`success`、`dns_failure`、`connect_timeout`、`connect_refused`、`auth_failure`、`tls_failure`、`protocol_failure`、`unexpected_status`、`target_failure`、`executor_unsupported`、`executor_crash`、`resource_limited`、`cancelled`。后三类基础设施错误不增加节点连续失败计数。

每条 Record 保存排队、DNS、连接、TLS、首字节、总耗时；不可用阶段为空。错误详情使用稳定码和脱敏摘要。

## 3. 默认 Probe Profile v1

| 角色 | URL | 方法 | 成功条件 | 重定向 | 最大响应 |
| --- | --- | --- | --- | --- | --- |
| proxy primary A | `https://cp.cloudflare.com/generate_204` | GET | 204 | 禁止 | 1 KiB |
| proxy primary B | `https://www.gstatic.com/generate_204` | GET | 204 | 禁止 | 1 KiB |
| direct control A | `https://cp.cloudflare.com/generate_204` | GET | 204 | 禁止 | 1 KiB |
| direct control B | `https://www.gstatic.com/generate_204` | GET | 204 | 禁止 | 1 KiB |

总超时 10 秒，连接超时 5 秒，TLS 超时 5 秒，固定 User-Agent `Mozilla/5.0`，不发送 Cookie、Authorization、Referer 或唯一 ID。Profile 是不可变 Revision；URL、状态码、DNS、CA、出口网络或 Header 变化都会产生新 Revision 并进入 Health Key。

每个常规周期根据 `HMAC(health_key, cycle_number) mod target_count` 确定主目标，避免所有节点集中到单站点。主目标失败时立即使用另一个目标确认；只有两者均出现节点归因失败才增加一次连续失败。目标自身失败或直连控制失败归为基础设施错误。恢复确认必须成功完成另一个目标，避免单站点假阳性。

管理员可替换全部目标为自建端点。自定义目标仍经过独立 Probe SSRF 允许列表；不能从节点内容自动生成目标。

## 4. Health Key

Health Key 投影包括：

- Effective Node 的协议、服务器、端口、认证、TLS、传输、DNS、detour 及影响拨号的扩展字段；
- Protocol/Format Adapter 和投影版本；
- Executor ID、精确版本、配置生成器版本；
- Probe Profile Revision（包含完整目标集合与期望结果）；
- Network Context Revision（DNS、CA、出站接口、IPv4/IPv6 策略）。

显示名称、来源、地区和 Output 标签不包括在内。投影使用独立 HMAC-SHA-256。未知协议若执行器不支持，不生成虚假的 real-probe Health Key，只记录 `unsupported` 能力状态。

同一 Health Key 且结果未陈旧时可复用物理 Record，但每个 Node Occurrence 都创建 NodeHealthLink 和独立状态转换。

## 5. 节点状态机

```text
unchecked --schedule--> checking
checking --supported success--> healthy
checking --1st/2nd node failure--> degraded
degraded --3rd consecutive node failure--> unhealthy
degraded --success--> healthy
unhealthy --success--> degraded(recovery_pending)
recovery_pending --2 min + success on alternate target--> healthy
recovery_pending --failure--> unhealthy
any --executor has no real probe--> unsupported
any --user disables--> disabled
```

- 只统计同一 Health Policy、Probe Profile 和 Effective Node 连续序列。
- `timeout`、认证、TLS 和协议错误分别计数，同时维护总的节点归因连续失败数。
- `checking` 是短暂派生状态，重启后有活动租约才恢复，否则回到此前稳定状态并重新排队。
- 初次检查一次真实成功即可从 `unchecked` 进入 `healthy`；从 `unhealthy` 恢复必须两次成功。
- Endpoint 成功不能把 `unsupported` 改为 `healthy`，只能作为单独展示结果。

首次失败在 1 分钟和 5 分钟快速复核；第三次节点归因失败进入 unhealthy。之后 10、20、30 分钟复查，再每 60 分钟；第一次恢复成功后 2 分钟使用另一个目标确认。

## 6. 批次与大面积失败保护

Batch Key：

```text
output_id + health_policy_revision_id + probe_profile_revision_id
+ executor_id/version + network_context_revision_id + 5-minute-window
```

Batch 开始时并行执行所有 direct control 目标，控制结果有效 5 分钟。Batch Item 按唯一 Health Key 计数，重复节点不放大样本。一次物理探测可以关联多个 Batch Item。直连控制使用独立 Control Probe Record，不创建虚假的节点 Health Key；相同 Probe Profile、Network Context 和窗口的控制结果可关联多个 Output 批次。

关闭条件是窗口结束且所有已领 Item 完成/超时，或最长 15 分钟。结论：

- 全部控制目标失败：`control_failure_suppressed`；无条件冻结本批次自动摘除。
- 任一控制可用、有效样本少于 10：`insufficient_sample`；不使用 50% 熔断，但仍按单节点防抖。
- 至少 10 个有效样本，节点归因失败率 >= 50%：`mass_failure_suppressed`。有效样本只包含 success 和 node-attributable failure；target、executor、resource、cancelled 和 unsupported 结果从分子与分母同时排除。
- 其他：`normal`。

“冻结摘除”只阻止本批次失败触发的健康过滤构建。已有 unhealthy 状态不被洗白，手工强制过滤不被静默覆盖；UI 要求管理员看到并确认基础设施告警。

## 7. 队列与优先级

优先级：手工复测 > unhealthy 恢复 > 新节点首次 > 失败复核 > 常规周期。同级按 `due_at, created_at, health_key` 稳定排序。

- 全局物理队列表以 Health Key 唯一化活动项；Probe Profile 已包含在 Health Key，task kind 和多个 Output 通过请求与 Batch 关联，不复制物理队列项。新的更高优先级提升已有项。
- 100,000 是持久化唯一待检查项硬上限，不是内存数组容量。
- 满载时先不生成最低优先级周期项，并记录 deferred 计数；手工项可替换一个尚未领租约的最低优先级周期项，绝不静默丢弃。
- 手工预留 2 个槽位包含在全局并发内；没有手工任务时可被普通任务借用，新手工任务到来不抢占已运行探测。
- 租约默认 30 秒并由 Supervisor 心跳；执行器超时后杀死进程组，Record 写入后再确认队列项。
- 长期未被任何启用 Output 使用的节点可不生成常规任务，但手工检查始终可用。

## 8. 并发限制

| 限制 | 默认 | 硬范围/上限 |
| --- | ---: | ---: |
| 物理探测总并发 | 16 | 1..64 |
| 手工预留槽位 | 2 | 0..8，且小于总并发 |
| 执行器子进程 | 4 | 4 |
| 同一服务器 IP | 4 | 16 |
| 同一探测目标 | 8 | 32 |
| 待检查唯一项 | 100,000 | 100,000 |

有效并发是全部限制的交集。资源压力控制器可按 CPU、内存、FD、错误率逐级降低到 1；恢复每分钟最多增加 1，且不超过管理员配置。它不能自动提高管理员上限。

## 9. 容量模型

忽略限流冲突时，完整覆盖时间近似为：

```text
T = unique_health_keys * mean_probe_seconds / effective_concurrency
```

20,000 个唯一 Health Key 的理论值：

| 平均物理探测耗时 | 并发 16 | 并发 32 | 并发 64 | 30 分钟所需并发 |
| ---: | ---: | ---: | ---: | ---: |
| 1 秒 | 20.8 分钟 | 10.4 分钟 | 5.2 分钟 | 12 |
| 2 秒 | 41.7 分钟 | 20.8 分钟 | 10.4 分钟 | 23 |
| 4 秒 | 83.3 分钟 | 41.7 分钟 | 20.8 分钟 | 45 |
| 10 秒 | 208.3 分钟 | 104.2 分钟 | 52.1 分钟 | 112（超出硬上限） |

实际还受同服务器/目标限制和失败二次确认影响。系统以最近 15 分钟成功与节点失败探测的截尾均值估算，并同时展示 P95 情景；预计周期超过 30 分钟显示 capacity warning，超过 60 分钟把无法及时覆盖的结果标记 stale。20,000 节点验收关注队列有界、服务可用和估算诚实，不要求在不可能的时延下违反资源上限。

## 10. 执行器协议

Supervisor 与驱动使用版本化 JSON Lines 控制协议，消息只在本机 pipe 传输：`hello`、`load`、`probe`、`result`、`shutdown`。`hello` 固定驱动、上游二进制版本、协议能力和最大活动探测。未知消息版本立即终止子进程。

单个临时配置可包含多个带随机内部 ID 的 outbound，但不得使用用户节点名。执行器监听端口只绑定 loopback，Supervisor 不向 API 暴露。每个结果必须包含 request ID、结果分类、阶段耗时和执行器诊断码；任何 stdout 非协议文本都按基础设施错误处理并限长保存。

## 11. 验收重点

M3 至少验证：Health Key 正反例、两个目标交叉确认、控制探测全失败、10/50% 边界、批次窗口隔离、恢复节奏、队列合并/满载、手工槽位、子进程崩溃/泄漏、20,000 项容量报告，以及健康风暴期间发布读取 P95。
