# ProxyLoom M2 实现状态

> 状态：In Progress，Deployment Preview 可部署测试
>
> 日期：2026-07-18
>
> 入口基线：[M1-EXIT-AUDIT.md](./M1-EXIT-AUDIT.md)

## 1. 当前结论

ProxyLoom 已形成可运行的 M2 纵向切片：独立 Master Key、SQLite migration、版本化 AEAD 与 Blob、Source/Snapshot/Raw Node/Occurrence、格式检测、内容门禁、持久刷新 Job、不可变 Artifact、稳定发布令牌、最小管理 API 和加固容器均已接通，并在真实 NAS Docker 环境完成构建、端到端与重启验收。

这仍不是 M2 出口。当前 Bearer 管理令牌是无前端测试入口，不能替代规范要求的首次管理员、Argon2id、Session/CSRF 和恢复流程；Source 编辑、完整 OpenAPI、托管备份恢复、Master Key 双 wrapping 轮换、前端、Mihomo 和健康执行器也尚未完成。

## 2. 已实现切片

### 2.1 加密与迁移

- `plmk1` Master Key 文件、`0600`/属主/符号链接检查和拒绝覆盖的初始化 CLI。
- AES-256-GCM 版本化信封及绑定 Instance/Record/Field/Version 的 AAD。
- `data`、`blob`、`fingerprint_hmac`、`health_hmac`、`token_hmac`、`content_hmac` 六类用途隔离 Key。
- inline/external 加密 Blob、内容 HMAC、公开 Artifact SHA-256 和外部文件原子发布。
- migration 连续版本、嵌入 SQL checksum、升级前 verified backup、事务回滚和 `quick_check`。

| Version | Name | SHA-256 | 范围 |
| --- | --- | --- | --- |
| 1 | `bootstrap` | `6423b07856ad565d9702d801f4ba29b9d01a11ff02822947ba76a28f078edd94` | metadata、Key Slot、Instance、Data Key、Wrapping、Blob |
| 2 | `sources` | `bc78fbf9daafbe975dada8987ea7ffa43b85398270659e56709fa065e27299bc` | Source、Revision、Attempt、Raw Document、Snapshot |
| 3 | `nodes` | `d8cda12dcd8e649a4a262e2eb340b17f87a2a11f000e83645afa2d8f0414e19a` | Fingerprint、Raw/Canonical Node、Occurrence、SnapshotOccurrence |
| 4 | `runtime` | `de9178983d49f15f3e573be49e34fe13e509eccb86cbfd97ef54495edef8aeef` | Job、Artifact、Publication、Publication Token |
| 5 | `sanitize_errors` | `4813488944e32b3c0cfd19ce9ebe7aedb850f465f06dd728f12c2418b5d227f6` | 清理历史 Job/Attempt 敏感诊断并恢复终态不可变触发器 |

### 2.2 Source、Snapshot 与节点事实

- Source 使用稳定 ID 和不可变 Draft/Published Revision；敏感配置存入 `source_config` Blob。
- Attempt 固定 Published Revision，同源只允许一个 running Attempt，终态不可修改。
- Snapshot、Raw Node、Canonical、Fingerprint、Occurrence 和 SnapshotOccurrence 在同一接受事务中持久化。
- 指纹 Key 必须为 `fingerprint_hmac` 用途；节点协议、指纹、Occurrence、匹配方法和算法版本交叉校验。
- rejected/failed Attempt 不移动最后有效 Snapshot；304 仓储路径复用已有 Snapshot。
- 接受事务中任何详情、Artifact 前置约束或指针切换失败都完整回滚。

### 2.3 格式、门禁与同格式输出

- sing-box 单节点、outbounds 数组和完整配置使用有界有序 AST；重复键稳定拒绝。
- URI 纯列表、标准 Base64 和 URL-safe Base64 使用单遍有界解析；未知合法 scheme 原样保存。
- Mihomo/Clash YAML 使用有界 AST，拒绝重复键、自定义标签和别名；识别 v1.19.28 的 21 类代理并原样保留未知代理对象。
- Surge/Loon `[Proxy]` 和 Quantumult X `[server_local]` 使用有界行解析，只提取显示名、原始类型和不含名称的身份投影；完整配置与未知字段原样保存。
- 自动检测 `sing-box`、`uri-list`、`mihomo` 与 `client-text`，节点协议支持范围由能力矩阵和开放注册表扩展，不与当前 Momo 节点绑定。
- `minimum_nodes` 和 `maximum_drop_ratio` 在 Snapshot 接受前执行。
- 无需改名时 Artifact 直接复用原输入字节，包括 JSON 空白、YAML 注释与排版和 Base64 包装。
- 重名时保留全部节点；sing-box 只修改原 Document AST 对应 `/tag`，Mihomo 只修改代理对象的 `name`，URI 只修改已声明为显示名的 fragment，客户端文本只修改赋值名称或 Quantumult X `tag=` 值。

### 2.4 Job、Artifact 与发布

- Job 状态支持 queued、leased、running 和终态；同源活动刷新去重，租约过期在启动时重排或 dead-letter。
- 成功刷新可按 `refresh_interval_seconds` 持久化下一次 due time。
- Artifact 内容先写加密 Blob，再在事务中写不可变元数据并切换当前发布指针。
- 数据库触发器拒绝发布非当前 Snapshot 构建的 Artifact；失败保留最后有效 Artifact。
- 发布令牌使用公开 UUID token ID 加 32-byte secret；数据库只保存 `token_hmac`，比较采用常量时间。
- 发布读取只访问当前 Artifact，支持 ETag、Last-Modified、HEAD、304 和 `nosniff/no-referrer`。

### 2.5 服务、API 与容器

- `proxyloom serve` 完成 migration、升级备份、Master Key 验证/首次 Key bootstrap、Blob/Store/Worker/API 装配和优雅关停。
- `/healthz`、`/readyz`、创建 Source、手工刷新入队、Job 查询、发布令牌补发和稳定订阅读取已实现。
- 预览 API 支持完整替换现有 Source 配置，使用不可变 Draft/Published Revision；新刷新失败时旧 Artifact 不受影响。
- 远程 Source 可加密保存自定义请求头；过滤 Host/hop-by-hop 头和控制字符，跨主机或协议重定向删除全部自定义头、Authorization 与 Cookie。
- 管理 API 使用独立 `0600` 256-bit Bearer Token 文件；验证常量时间且 CORS 默认不开放。
- 网络、解析和 Job 错误使用不含订阅 URL、凭据或目标地址的稳定诊断；v5 migration 清理旧版本遗留的敏感错误文本。
- Docker 多阶段静态构建；运行镜像为 distroless nonroot。
- Compose 固定 UID/GID 65532、只读 rootfs、drop all capabilities、`no-new-privileges`、独立数据/secret 卷和受限 tmpfs。

## 3. 自动化与部署证据

| 场景 | 结果 |
| --- | --- |
| migration v1-v5 空库重放、checksum、过新版本、失败回滚、敏感错误清理和升级备份 | PASS |
| Master Key/Keyring/AEAD/Blob 正负向与篡改测试 | PASS |
| Snapshot 事务、跨 Source、最后有效指针和 Node/Occurrence 持久化 | PASS |
| sing-box、URI、Mihomo YAML、Surge/Loon/Quantumult X 无损、重复节点和名称最小 Patch | PASS |
| 管理认证拒绝、持久 Job、发布、ETag/304 和服务重开 | PASS |
| Worker 过期租约恢复为 queued | PASS |
| `go test ./...`、`go vet ./...`、Go race test | PASS |
| Linux amd64/arm64 `CGO_ENABLED=0` 静态构建 | PASS |
| NAS Docker Engine 28.5.2 / Compose v2.40.3 实际镜像构建 | PASS |
| NAS 非 root、只读 rootfs、cap-drop、健康检查、端到端和容器重启 | PASS |
| 现有 Sub-Store 9 个 Source 迁移、手动刷新和发布 | PASS（9 个 healthy，共 254 个节点） |
| Momo 设备实际 sing-box 静态校验与隔离流量测试 | PASS（HTTP 204，正式 Momo PID 未变化） |

真实 NAS 验收中，两个同名 URI 节点均被保留，第二个获得 `#2`；容器重启后同一发布 URL 的响应内容和 ETag 均未变化。

同日将现有 Sub-Store 的 9 个 Source 迁入独立 NAS 预览实例，全部保持手动刷新且未写入正式 Momo 配置。两份 Base64 URI 订阅发布 72 和 19 个节点，两份 48 万字节 Mihomo YAML 原文分别发布 7 个 VMess 节点；一份带 Sub-Store 专用 URL 参数且上游直连超时的来源，从 Sub-Store 当前可读内容迁成 106 个 VLESS 节点的加密 inline 静态快照。GET、HEAD、ETag/304、容器重建和失败隔离均通过。

同一 VPS Panel 分享 ID 更新后，Clash、Surge、Quantumult X 和 Loon 四个远程 Source 均成功迁移。Clash 原生 YAML 发布 16 个节点；Surge、Quantumult X 和 Loon 原生文本分别发布 8、12 和 7 个节点，覆盖 VMess、VLESS、Shadowsocks、AnyTLS、Hysteria2 和 TUIC；四个 Artifact 的 SHA-256 均与源站本次原始响应一致。9 个迁入 Source 最终全部 healthy，共 254 个节点，活动 Job 和 Job/Attempt 敏感 URL 特征计数均为 0。

Sub-Store 使用 `sing-box` User-Agent 生成的 16 节点 JSON 先在 Momo 设备的实际 `sing-box 1.13.14-urltestfix.4256` 上通过 `check`，再经 ProxyLoom 加密 Snapshot/Artifact 发布后由 Momo 直接拉取；两份内容 SHA-256 相同。随后使用只监听 `127.0.0.1:19090` 的独立临时实例和 Momo 相同 `node_dns` 配置运行 URLTest，HTTPS 代理请求返回 204。测试结束后临时进程、配置和缓存均删除，正式 Momo PID 未变化且服务保持 running。NAS 的透明 fake-IP DNS 仅通过 ProxyLoom 容器的测试专用 `extra_hosts` 处理，未修改宿主或正式 Momo 网络配置。

## 4. 未完成项

1. 首次管理员 Bootstrap Token、Argon2id 密码、Session/CSRF、限速、恢复与完整安全审计。
2. Source 列表/编辑/归档、Output/Pipeline/Collection、幂等键和完整 OpenAPI 对齐。
3. Master Key prepared/active 双 wrapping 轮换、Data Key 轮换、托管备份恢复和保留清理。
4. Mihomo proxy-provider、JSON/JSONC、逐协议 Canonical、跨格式转换、完整客户端配置校验和目标客户端验证，以及后续客户端专有格式。
5. M3 真实健康执行器、批量故障保护、历史状态与健康过滤。
6. Vue 管理前端、镜像发布/SBOM/签名和 ARM Docker 实机验收。

当前 Deployment Preview 的使用和边界见 [deployment-preview.md](./deployment-preview.md)。
