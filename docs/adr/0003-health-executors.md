# ADR-0003：健康执行器、批次与容量边界

- 状态：Accepted
- 日期：2026-07-17
- 对应决策：D-003、D-004、D-007、D-010、D-011、D-018、D-019

## 背景

端口可连接不能证明代理可用，而把代理内核链接进核心进程会扩大崩溃和许可证边界。20,000 个节点的设计上限也使固定 16 并发与 30 分钟周期不能在任意探测耗时下同时成立。

## 决策

P0 采用版本化外部执行器接口，镜像集成 sing-box 驱动。执行器池最多 4 个子进程，每个进程可承载多个受限探测；每次探测只接收最小临时配置和随机内部关联号，输出结构化结果，不输出节点秘密。

默认全局并发 16，管理员可在 1 至 64 内设置。同一服务器 IP 默认/硬上限为 4/16，同一探测目标为 8/32，手工任务在全局并发中保留 2 个槽位。执行器进程硬上限始终为 4。

30 分钟是期望调度周期。调度器用最近 15 分钟探测服务时间的 EWMA 与 P95 同时估算：

```text
required_concurrency = ceil(unique_health_keys * observed_mean_seconds / desired_cycle_seconds)
estimated_cycle      = unique_health_keys * observed_mean_seconds / effective_concurrency
```

估算值超过配置上限或 1 小时陈旧期限时告警，不自动突破上限。管理员需要明确增加并发、减少探测目标、启用懒检查或接受陈旧结果。

### 批次定义

`ProbeBatch` 的身份由 Output、Health Policy Revision、Probe Profile Revision、Executor Version、Network Context Version 与 5 分钟调度窗口组成。批量失败保护只统计同一批次已完成的唯一 Health Key。物理探测可被多个批次项引用，但各批次分别评估：

- 少于 10 个完成项不触发 50% 规则。
- 至少 10 个完成项且失败率达到 50%，该批次的自动摘除被冻结。
- 该批次全部直连控制目标失败时，无条件冻结。
- 冻结只阻止健康过滤导致的新摘除，不把失败改写为成功，也不影响手工查看与复测。

## 后果

- P0 的真实检查范围以 sing-box 驱动能力为准，首批是 Shadowsocks、VMess、VLESS、Trojan、Hysteria 2、TUIC、AnyTLS。
- 满规模是否按 30 分钟覆盖取决于实际服务时间；UI/API 必须展示估算和覆盖率。
- Mihomo 驱动进入 P1 前必须单独完成许可证、协议和资源隔离评审。
