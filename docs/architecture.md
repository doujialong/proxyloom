# ProxyLoom M0 系统架构

> 状态：M0 Baseline
>
> 日期：2026-07-17
>
> 规范来源：[REQUIREMENTS.md](../REQUIREMENTS.md)

## 1. 范围与质量属性

首个完整版本是单租户、单实例、自托管服务。设计优先级依次为：不丢字段、失败时继续提供最后有效结果、敏感数据安全失败、确定性构建、可解释处理、受限资源运行。M0 不设计公共 SaaS、多租户、集群调度或长期代理网关。

最低参考环境为 2 vCPU、2 GiB 内存、SSD、本地 Docker、`linux/amd64` 或 `linux/arm64`。一个实例设计管理 100 个来源和 20,000 个节点；这个数字是存储与调度上限，不代表默认 16 并发能在任意网络时延下每 30 分钟检查全部节点。

## 2. 系统上下文

```text
Browser / API client
        |
        | HTTPS via trusted reverse proxy, or trusted LAN HTTP
        v
+------------------------+
| ProxyLoom service      |
| API + UI + scheduler   |
| domain + SQLite        |
+------------------------+
   |          |        |
   | HTTPS    | exec   | stable subscription URL
   v          v        v
Sources    sing-box   Proxy clients
Templates  validator  (Momo/sing-box)
Probe URLs executor
```

外部来源、模板、节点服务器、探测端点和浏览器请求全部跨越信任边界。ProxyLoom 不信任订阅内容，也不把代理内核视为内存安全边界内的库。

## 3. 运行时组件

| 组件 | 职责 | 禁止事项 |
| --- | --- | --- |
| HTTP/API | 认证、CSRF、请求限制、OpenAPI DTO、发布端点 | 直接拼 SQL、同步执行全量刷新/构建 |
| Application | 用例编排、事务、权限、幂等、审计 | 解析协议私有字段 |
| Domain | 修订、快照、Occurrence、命名、健康和发布策略 | 依赖 HTTP/SQLite/具体内核 |
| Format Registry | 格式检测、Raw Node 切分、显示字段规则 | 删除未知字段 |
| Protocol Registry | 协议 ID、标准化、身份投影、能力矩阵 | 用单一布尔值声称“全支持” |
| Patch Engine | 路径白名单、最小修改、差异、冲突检测 | 从 Canonical Node 重建同格式节点 |
| Build Engine | 固定输入、流水线、命名、模板合并、验证、Artifact | 在发布请求线程运行 |
| Health Scheduler | Health Key、批次、队列、状态机、熔断 | 把 TCP 成功标成代理健康 |
| Executor Supervisor | 子进程池、临时配置、配额、结果协议 | 记录原始凭据或开放外部监听端口 |
| SQLite Store | 仓储、迁移、租约、不可变记录、原子切换 | 在 NFS/SMB 上承诺可靠写入 |
| Crypto Service | AEAD、HMAC Key、轮换、密文版本 | 把 Master Key 写入数据库 |
| Blob Store | 数据目录内的加密 Raw/Artifact 大对象 | 写入未加密敏感临时文件 |

模块依赖必须遵守 [ADR-0001](./adr/0001-stack-and-boundaries.md) 和[适配器契约](./adapter-contract.md)。格式适配器和协议适配器分开：格式层知道 sing-box 的顶层 `tag`，协议层知道 VLESS 的连接字段；未知协议仍可由格式层切分和无损保存。注册表按 `(format_id, raw_type)` 寻址，Identity 只消费适配器提供的版本化投影；Occurrence、命名和 HMAC 核心不得导入 sing-box、Mihomo 或 URI 私有字段。

## 4. 数据与文件布局

```text
/var/lib/proxyloom/              # 唯一业务数据目录，0700, uid 65532
  proxyloom.db                   # SQLite WAL
  blobs/                         # 加密 raw/template/artifact blobs
  backups/                       # 可选本地加密备份暂存
/run/secrets/proxyloom/           # 独立只读目录挂载；master.key 为活动文件
/tmp/proxyloom/                  # 有大小上限 noexec,nosuid tmpfs
```

数据库保存索引、状态和密文引用；Raw Document、Raw Node 大对象、模板和 Artifact 内容通过 Blob Store 保存。Blob 文件名是随机 ID，不含来源或节点名称。数据库提交前 Blob 先以临时名完整写入、`fsync`、原子改名；失败事务产生的孤儿 Blob 由保守清理任务回收。

SQLite 启用 WAL、foreign keys、busy timeout，并在启动时获取实例锁。模式迁移前创建并验证备份，迁移和运行时模式版本不兼容时 readiness 失败。

## 5. 核心流程

### 5.1 来源导入与刷新

```text
create/refresh request -> durable Job -> SSRF-safe fetch
  -> encrypted Raw Document -> format detect -> bounded parse preview
  -> validity gates -> transaction:
       Refresh Attempt
       accepted Snapshot
       Raw Nodes + Canonical views
       Occurrence reconciliation
       current_snapshot_id switch
  -> enqueue affected builds / health checks
```

拉取失败或有效性门槛失败只写 Refresh Attempt，不切换 `current_snapshot_id`。远程来源把连续失败次数和下次重试保存到 Refresh Attempt 与 durable Job；默认按约 1、3、10、30、60 分钟退避，`Retry-After` 在上限内优先采用，容器重启不会丢失重试链。快照陈旧期限独立于刷新周期，默认 72 小时。从未成功的来源不能以空列表参与构建。条件请求 `304` 记录成功刷新，但复用已有 Snapshot，不复制 Raw Document。

远程 Template 使用同一 SSRF、重定向、超时、响应大小和请求头策略。模板首次创建必须成功拉取并通过完整配置、无代理节点、占位符和引用校验；周期或手工刷新先在内存中验证，只有内容摘要变化时才切换模板修订并给关联 Output 排队。失败继续读取加密保存的最近有效模板，调度器按有上限的指数退避重试，重启后从资源更新时间和刷新周期恢复计划。

### 5.2 构建

1. 在事务中固定 Output Revision、所有资源修订、Snapshot、Name Allocation 当前版本和健康策略。
2. 展开 Raw Nodes，运行确定性流水线；连接补丁形成 Effective Node。
3. 在 Output 范围内对全部候选节点分配或恢复稳定名称，创建包含被健康过滤节点的不可变 Name Allocation Snapshot。
4. 关联精确 Health Record，计算陈旧属性和批次保护结论，再按策略过滤；过滤不释放或改变名称。
5. 对保留节点执行名称及用户 Patch：同格式从 Raw Node 的有序无损 AST 应用最小修改；跨格式从 Canonical Node 渲染并报告降级。
6. 合并模板、检查引用、运行目标验证器。
7. 写入 Artifact、构建清单、差异和验证结果。
8. 通过比较并交换切换当前发布 Artifact；旧输入晚完成不能覆盖新输入。

任何阶段失败都保留最后有效 Artifact。预览 Artifact 与已发布 Artifact 分开，预览永远不会被发布 URL 读取。

### 5.3 健康检查

调度器对 Effective Node、执行器版本、Probe Profile 和网络上下文计算 Health Key。全局 Probe Queue 按 Health Key 合并物理探测，Batch Item 只关联同一个 Queue Item 和 Health Record；直连控制写入不依赖 Health Key 的 Control Probe Record。Executor Supervisor 将最小配置送入 sing-box 子进程，结构化结果进入不可变 Health Record，再由状态机更新每个 Node Occurrence 的派生健康状态。

基础设施熔断只阻止批量摘除，不伪造 Health Record。健康跨越发布过滤边界时合并触发受影响 Output 构建。

### 5.4 发布读取

发布令牌经 HMAC 常量时间校验后，只读取 `output_publications.current_artifact_id`。响应支持 ETag/Last-Modified 和条件请求，不查询节点表、不触发构建。数据库短暂写忙不应阻塞已构建小文件读取；Artifact 元数据在进程内有带版本缓存，内容从只读 Blob 读取。

## 6. 修订、任务与并发

- Source 配置、Collection、Pipeline、Template、Output、Health Policy、Probe Profile 都是“稳定资源 ID + 不可变 Revision”。
- API 修改必须带 `If-Match`；发布 Revision 是显式动作。
- Job 状态为 `queued -> leased -> running -> succeeded|failed|cancelled|dead`。租约包含 owner、过期时间和 attempt。
- 同一资源的刷新使用唯一活动键；同一 Output 的构建触发按输入摘要合并。
- 幂等键作用域是主体 + 方法 + 规范路径，保存 24 小时；相同键不同请求摘要返回冲突。
- 关停停止领新租约，给运行任务 30 秒宽限；未完成任务释放或等待租约超时恢复。

## 7. 失败隔离

| 故障 | 行为 |
| --- | --- |
| 来源超时/解析失败 | 保留最后有效 Snapshot，来源 degraded/unhealthy |
| 单节点解析失败 | 保留 Raw Node 与警告；其他节点继续，除非来源门槛失败 |
| 未知协议 | 同格式保存/输出；标准化、转换和真实检查标为未实现 |
| 执行器崩溃 | 当前探测记 infrastructure error，监督器限速重启，不影响发布读取 |
| 大面积探测失败 | 批次熔断健康摘除，继续服务最后有效 Artifact |
| 目标验证失败 | Artifact 不可发布，当前 Artifact 不变 |
| 错误 Master Key/AEAD 失败 | readiness 失败，管理和发布接口不开启 |
| SQLite 迁移失败 | 恢复前备份或保持停止，不以半迁移模式运行 |
| 磁盘不足 | 停止接受写任务并告警，已可安全读取的 Artifact 尽量继续提供 |

## 8. M1 实现顺序约束

M1 先实现不联网的纵向切片：sing-box JSON Raw Document -> Raw Node -> Canonical view -> Occurrence -> Name Allocation -> 最小 `tag` Patch -> 确定性 Artifact。sing-box 只是首个验证适配器，不是产品范围上限；该切片还必须证明核心身份、Occurrence 和命名不依赖具体格式，后续 URI、Mihomo 与客户端专有格式按同一适配器契约接入。首个切片通过未知字段、重复节点、顺序变化、消失/回归和重放 golden tests 后，才能接入 HTTP、任务调度与真实健康执行器。

## 9. 关联设计

- 数据模型：[data-model.md](./data-model.md)
- 安全与加密：[security.md](./security.md)
- 健康检查：[health-check.md](./health-check.md)
- 可复现构建：[reproducible-builds.md](./reproducible-builds.md)
- SQLite Schema：[../db/schema.sql](../db/schema.sql)
- OpenAPI：[../api/openapi.yaml](../api/openapi.yaml)
