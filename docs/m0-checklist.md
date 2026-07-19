# ProxyLoom M0 设计准入检查

> 结论：**M1 PASS；Momo Target Profile 来源身份已核验，无待确认项**
>
> 评审日期：2026-07-17；增量证据复核：2026-07-18
>
> 最新评审记录：[M0-REAUDIT.md](./M0-REAUDIT.md)

## 1. 必需产物

| 准入项 | 产物 | 结果 |
| --- | --- | --- |
| 产品范围与已确认决策 | [REQUIREMENTS.md](../REQUIREMENTS.md) v0.8，D-001 至 D-021 | PASS |
| 项目标识、许可证与版本 | [README.md](../README.md)、[LICENSE](../LICENSE)、ADR-0005 | PASS |
| 模块、进程与部署边界 | [architecture.md](./architecture.md)、ADR-0001 | PASS |
| 无损/身份/命名模型 | ADR-0002、[data-model.md](./data-model.md) | PASS |
| 数据库物理草案 | [schema.sql](../db/schema.sql)，可由 SQLite 完整加载 | PASS |
| 威胁模型与加密 | [security.md](./security.md)、ADR-0004 | PASS |
| 健康状态机、批次与容量 | [health-check.md](./health-check.md)、ADR-0003 | PASS |
| 可复现构建与原子发布 | [reproducible-builds.md](./reproducible-builds.md)、ADR-0006 | PASS |
| REST、错误、异步与幂等 | [openapi.yaml](../api/openapi.yaml)、[api-conventions.md](./api-conventions.md) | PASS |
| 六维协议能力矩阵 | [protocol-matrix.yaml](./protocol-matrix.yaml)，26 个初始条目、21 个 Mihomo v1.19.28 canonical proxy type | PASS |
| 设计复审 | [M0-REAUDIT.md](./M0-REAUDIT.md) 三轮确定性问题均处理 | M1 PASS |

## 2. 已冻结决定

- P0 目标固定为 Momo v1.2.1 + sing-box v1.12.25 组合目标与独立上游 sing-box v1.12.25；sing-box v1.13.14 是首个兼容性目标。
- Go + SQLite + Vue 3/TypeScript，单服务容器，非 root UID/GID `65532:65532`。
- 一个加密数据目录；`master.key` 位于卷外并只读挂载。
- Raw Node 与 Canonical Node 双表示；同格式只应用最小 Patch。
- 所有重复节点保留；` #2`、` #3` 分配持久化 30 天且不自动递补。
- 未知协议使用不透明结构指纹，不声称语义重复，仍可同格式无损直通。
- 健康默认并发 16、可配置 1 至 64、4 个执行器子进程、队列 100,000；30 分钟是容量可观测的目标而非虚假硬保证。
- Batch、Control Probe Record、Health Key、Name Allocation Snapshot 和精确 Health Record ID 都进入可复现构建边界。
- 首次管理员必须使用本机一次性 Setup Token，避免空实例被网络用户抢注。

## 3. M1 入口约束

M1 只开始“不联网的无损内核”纵向切片，不同时铺开 Web、调度器和健康执行器：

1. 建立 Go module、目录边界和最小 CI。
2. 实现 sing-box JSON 有界解析、Raw Document/Raw Node 与原始数字词法保存。
3. 实现协议注册表骨架、未知协议、Fingerprint v1 和 Occurrence v1。
4. 实现稳定 Name Allocation 与只修改 `/tag` 的 Patch Engine。
5. 生成 `outbounds` Artifact，并先通过 AC-001、AC-003、AC-009、AC-015、AC-019 和 AC-023 的 M1 部分。

M1 不得把 SQLite Schema 草案直接当成无需迁移评审的最终 Schema。首个实际 migration 必须计算真实 SHA-256，并通过从空库构建和回滚备份测试。

## 4. 非阻塞后续事项

这些项目需要在对应阶段完成，但不阻塞 M1：

- 引入 sing-box/Mihomo 二进制时锁定发布资产 SHA-256、许可证和源码获取信息。
- M1 收集脱敏协议 fixture 并把矩阵维度从 `not_implemented` 按测试证据逐项升级。
- M3 在参考设备和用户实际 NAS 上校准执行器池、EWMA 容量模型与公共探测流量。
- M4 完成 P0 Web 交互与 360 px 到桌面视口验证。
- M4 使用已锁定的 Momo v1.2.1 x86_64/OpenWrt 25.12 发布资产与 sing-box v1.12.25 构建 wrapper/core 组合 fixture；来源 verified 不得被误报为目标校验 implemented。
- 首次公开源码仓库使用用户授权的 `doujialong/proxyloom`；正式 Release 和镜像发布前仍需重做名称/商标终检。

## 5. 已关闭确认项

**C-001 Momo v1.2.1 的权威发布定位：已关闭。** 官方仓库、Release、标签 commit、许可证和 x86_64/OpenWrt 25.12 资产 SHA-256 已写入 ADR-0005 与协议矩阵。用户参考设备实测为 Momo v1.1.0 + 定制 sing-box v1.13.14，仅作为兼容性观察；当前没有待用户确认的问题。
