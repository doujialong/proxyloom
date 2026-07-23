# ProxyLoom M4 部署测试状态

> 日期：2026-07-19
>
> 结论：已通过隔离 NAS 验收，可继续受控预览，尚未达到公开 Beta 准入。

## 已接通

- 原始 sing-box、Mihomo、Surge/Loon/Quantumult X 和 URI/Base64 Source 直接导入，不经过 Sub-Store。
- 同格式无损发布、未知协议保留、重复节点稳定数字后缀、健康状态与来源快照持久化。
- Collection、Pipeline、sing-box 完整 Template、Momo/sing-box Output、后台构建和稳定只读令牌。
- Template 逻辑出站标签预留；`${PROXYLOOM_NODES}` 展开全部节点，`${PROXYLOOM_NODES_REGEX:<re2>}` 按最终稳定名称选择节点。
- Template 支持内联内容或 GitHub Raw/HTTP(S) URL；远程 URL、请求头和最近有效内容加密保存，支持 60 秒到 7 天的手工/定时刷新、摘要去重、失败回退和关联 Output 补偿重建。
- 来源刷新和集合更新自动生成去重 Output Build Job；仅开启健康过滤的 Output 会在过滤边界变化时重建，租约过期可在重启后恢复。
- Source 无损发布与目标版本解耦；Output 按 Profile 使用 sing-box v1.12.25 或 v1.13.14 `check`，并保留内容门禁和最后有效 Artifact 保护。
- Argon2id 管理员、HttpOnly Session、CSRF、登录限速、本地恢复、托管加密备份/恢复、Master Key 和 Blob Data Key 轮换。
- Vue 3 + TypeScript 管理端；桌面、390×844 移动视口和浏览器控制台冒烟检查通过。
- 容器固定非 root、只读 rootfs、无 capability、独立 Master Key、受限 tmpfs。

## 上机前自动化证据

- `go test ./...` 与 `go vet ./...`。
- 聚合端到端：sing-box Raw AST 保留、URI 转换、模板合并、逻辑标签冲突、正则分组、稳定重排、自动任务、令牌轮换和重启读取。
- 失败端到端：模板含代理节点拒绝、内容门禁拒绝、目标验证拒绝、当前 Artifact 不切换、临时 Blob 回收。
- 版本端到端：Naive Raw Source 原样发布，1.12 目标拒绝且不发布，1.13 目标通过并记录精确校验器版本。
- 前端：TypeScript 生产构建、npm 高危审计为 0、CSP/缓存/SPA 路由测试和真实 Chrome 截图。

## 隔离 NAS 验收证据

- 预览实例仅绑定文档保留地址 `192.0.2.228:18081`；未修改 Momo、Sub-Store 或宿主网络配置。
- Compose 项目独立 bridge 已启用 IPv6，使用 `fd12:7072:6f78:796c::/64` ULA 和 Docker 自动分配的 IPv4 子网；容器内到公网 IPv6 的 TCP 探测成功。未修改 NAS 默认路由、其他 Docker 网络或 Momo 路由。
- 原始 sing-box Source 直接导入 ProxyLoom，得到 122 个代理节点、3 个来源逻辑出站和 0 条解析警告。Source 发布内容与上游逐字节一致，SHA-256 均为 `51295f0ab5532266a4a4e3bd3da65afc47c560dea32cfee747481b23c449ade0`。
- 完整配置 Output 的 1.12.25 目标按预期拒绝 5 个 Naive 节点，未发布 Artifact，订阅端保持 503；1.13.14 目标成功发布 122 个代理节点和 2 个模板出站。全部 124 个标签唯一，Selector 完整引用 122 个代理节点。
- 1.13 Artifact 记录 `sing-box-1.13.14-check`，内容 SHA-256 为 `820814dff57f95806e3d274353356ecd061734f7385e22ca5690916a4296bc18`，排除数和警告数均为 0。
- 容器重建后 Source、Output 和当前 Artifact ID 均保持不变；SQLite 外键检查为 0，v5 到 v10 的迁移前备份存在。
- 本次健康观察中 122 个节点均已进入队列：10 个 healthy、103 个 unhealthy、9 个 unsupported。健康执行器仍为 sing-box 1.12.25；9 个不可执行节点进入 dormant。测试 Output 关闭健康过滤，因此发布内容仍保留全部 122 个节点。
- 上机时发现健康过滤关闭的 Output 仍会收到边界重建任务，造成相同 Artifact 重复发布。修复和回归测试后，30 秒观察窗内 Artifact 与健康边界任务计数均保持稳定；开启健康过滤的 Output 仍会正常排队。
- NAS `linux/amd64` 镜像由 Go 1.25.12 和 Node 22.17.1 构建，镜像 ID 为 `d7153961d4b19ca85a0e2af350a88b98a5eda8bf553ca2a1a19cc717f6d73edc`。Go 1.25.12 环境下 `govulncheck` 报告 0 个可达漏洞。
- 重建后的 `/healthz`、`/readyz`、管理 UI 和 JS 资源均返回 200；CSP、安全响应头、非 root、只读 rootfs、`cap_drop=ALL` 和 `no-new-privileges` 均生效。

## 最终审计与 Sub-Store 原始来源回归

- 直接读取 Sub-Store 持久化配置中的 9 个原始 URL/原始单节点内容导入 ProxyLoom；未使用 `/subs`、Sub-Store 转换端点或本地 `:3003` 地址，未修改 Sub-Store、Momo 或宿主网络配置。
- 最终有效快照共 521 个节点、0 条解析警告；9 个 Source 的同格式发布端点均返回 200，因此包括未知字段和 25 个带证书指纹的 Hysteria2 URI 在内的原文仍可发布。
- 审计修复了 Quantumult X `obfs-host` 到 TLS SNI/WS Host 的映射、Reality 必需的 uTLS 启用、Hysteria2 分号端口列表、连字符端口范围和无单位秒值。对应单元测试、全量 Go 测试、race 和 vet 均通过。
- Loon 的 `alpn=http1.1` 是客户端方言，sing-box 要求 IANA 值 `http/1.1`。增加规范化和回归测试并重建隔离镜像后，同一来源的 92 个 IPv6 Trojan 从 0 个健康恢复为第二轮观察时 75 healthy、12 degraded、5 unhealthy；healthy 最新成功记录平均 1861 ms。剩余 degraded/unhealthy 的最新记录为超时或真实代理请求失败，不再是统一的 ALPN 配置错误。
- `dash` 的 11 个和 `cfnew` 的 14 个 Hysteria2 URI 使用 `pinSHA256`。官方 Hysteria 2.6.4 对完整叶证书 DER 做 SHA-256，并在 `insecure=false` 时先执行系统 CA/主机名校验；sing-box 的 `certificate_public_key_sha256` 只校验公钥且主动跳过标准证书校验，语义不等价。
- 25 个原节点均带 SNI 且显式 `insecure=false`。隔离 QUIC 抽查中 12 个节点在 8 秒内返回与 pin 完全匹配的证书，13 个无响应；返回的 12 张实例全部是无 SAN 的自签名 CA，合计 6 个不同证书且均未过期。官方 Hysteria 会因旧式 Common Name/无 SAN 在 pin 回调前拒绝其中的实测节点；把证书嵌入 sing-box 也无法保留原主机名校验，改用公钥 pin 则会降低安全语义。因此全量 sing-box 聚合继续明确拒绝这 25 个节点并保留旧 Artifact，同格式发布仍逐字节保留，不静默丢字段或改成 `insecure=true`。
- 精确排除上述 25 个不可等价节点后，496 个输入节点成功生成 498 个出站，其中包含 6 个可转换 Hysteria2 和 2 个 ShadowTLS 辅助出站。Loon ALPN 修复后的当前 Artifact 由 sing-box 1.13.14 实际校验通过，为 189330 字节，SHA-256 为 `2f4169df621b09d8fcb3688b92a9956f9e985c8dcdfd1e84f2b1c04a3c488534`，警告和健康排除均为 0。
- 当前复测镜像 ID 为 `023e32019746a68af040e0ca42ea9081541e34b85f9325fdf5a508d842d8dc6b`。容器固定 `65532:65532`、只读 rootfs、`cap_drop=ALL`、`no-new-privileges`，SQLite 外键检查为 0，`/healthz`、`/readyz` 和管理页面均返回 200；部署端口参数已固化在 NAS 测试目录的 `.env`，重建后仍绑定文档保留地址 `192.0.2.228:18081`。
- 节点健康队列在 NAS 当前网络环境触发 `mass_failure_suppressed`，健康过滤因此被保护性关闭；测试 Output 本身也未启用健康过滤。没有把异常环境下的批量失败误判成节点失效。
- 最后一轮刷新时一个私有 Surge 来源上游连续三次在 15 秒内无响应；ProxyLoom 按设计保留其最近一次成功的 101 节点快照和可用 Artifact。该现象是当前外部上游状态，不是解析或转换失败。
- Node 22.17.1 固定镜像中的 Vue TypeScript/Vite 生产构建通过。一次额外的干净 `npm ci` 因 NAS 到 npm registry 的连接被重置而失败；此前相同锁文件的干净安装报告 0 个漏洞。

## 远程模板刷新验收

- 远程模板存储、HTTP API、手工刷新、自动到期、重启恢复、坏模板保留最近有效内容、内容未变化不增加修订、关联构建失败后补偿入队均有端到端测试；`go test ./...`、`go vet ./...` 及 fetcher/aggregate/service race 测试通过。
- 管理页面可选择远程 URL 或内联内容，配置周期、请求头和私网授权；模板列表显示脱敏来源并提供手工刷新。Node 22.17.1 容器中的 `vue-tsc -b` 与 Vite 生产构建通过。
- NAS 的 Momo DNS 对 `raw.githubusercontent.com` 返回 `198.18.0.0/15`/ULA fake-IP，默认 SSRF 策略按设计拒绝；对单个模板显式开启私网授权后，ProxyLoom 已实际下载 GitHub Raw 文件并进入完整模板校验。
- GitHub 当前 `sub-momofake.json` 尚未包含节点占位符，实机返回 422 且未创建坏模板。本地文件已加入地区正则、全节点占位符和空组直连回退，并通过 JSON 与 ProxyLoom 完整模板校验；用户上传后可完成正向远程创建。
- 当前隔离镜像 ID 为 `d3d9b06bf4eff434c82d1ab845939de8047b45872c3a3da8da61bea0e8ec3e60`，容器 healthy，仍绑定文档保留地址 `192.0.2.228:18081`，IPv6 地址为 `fd12:7072:6f78:796c::2`。未修改 Momo、Sub-Store、宿主路由或现有 Output。

## ECH、订阅代理与私有原始来源验收

- Source 配置新增每源 HTTP、HTTPS、SOCKS5、SOCKS5H 拉取代理和 1 至 120 秒超时，代理 URL 与凭据随 Source 配置加密保存；管理 API 只返回是否已配置及脱敏位置。目标 URL、重定向和代理本身仍执行私网授权与 SSRF 校验。
- Docker 构建允许覆盖 `GOPROXY`；NAS 到默认 Go 模块源超时后，使用实测可达的 `https://goproxy.cn,direct` 完成可重复构建。Vue TypeScript/Vite 生产构建、`go test ./...`、`go vet ./...` 和两份 OpenAPI YAML 解析均通过。
- 在同一私有入口的多种客户端格式中选择上游原始 sing-box 作为唯一正式来源，复用已有 Source，没有创建重复 Source。该 Source 使用 `socks5h://192.0.2.10:1080` 拉取、60 秒刷新和 30 秒请求超时；实机成功快照为 123 个节点、0 条警告，连续自动刷新返回 HTTP 200。
- 修复了周期 Source 在一次普通网络失败后不再安排下一次任务的问题。回归测试验证失败 Job 保留诊断并按 Source 周期创建新 Job；实机手工恢复后，下一条 60 秒周期 Job 自动执行成功，123 节点耗时约 8 秒。
- sing-box 1.13.14 现在专门执行包含 ECH 的节点健康检查；升级时旧 `executor_unsupported` 状态会重置并重新排队。NAS ECH 样本从旧 `ech_probe_not_verified` 变为 HTTP 204 成功，耗时 1878 ms，API 和管理端会显示实际 `executor_id` 与 `executor_version`。
- 正式候选先在独立 Collection/Output 验证，再更新正式 Collection。同一私有入口的 Loon、Quantumult X、Surge、Clash 四份重复转换来源仅从正式集合移除，原诊断 Source 和历史仍保留；正式集合现为 6 个真实原始来源。
- 验收时的新正式 Artifact 为 256188 字节、306 个代理节点，其中 103 个 ECH 节点、92 个 IPv6 节点；SHA-256 为 `163901db2baa7c4faa25667703eedf05548270dff32611563e204cf58081b452`，由 sing-box 1.13.14 实际校验通过。Artifact ID 会随后续成功快照正常更新；测试使用不撤销旧凭据的新令牌，没有主动要求 Momo 重拉。
- 升级前加密托管备份为 228315417 字节，SHA-256 为 `dd9e0da11d69cf38c25a952eef6fb622d6f9ddf5900c06dce29b144dc2596e85`。当前 NAS 镜像 ID 为 `ced77e8b4fdeb63d1a53c4de1aed368ea959e2e0db4d997a1e751f0bb06bccbc`，容器 healthy，仍绑定文档保留地址 `192.0.2.228:18081`。

## 归档健康数据与存储压缩复核

- 2026-07-23 复核发现 5 个已归档来源仍保留 431 个 `present` 节点及逾期健康队列，导致管理端把 226 个真实活跃节点显示为 657 个。修复后归档操作会把节点置为 `retired`，节点列表、手工复测、健康容量和快照同步均要求父 Source 为 `active`，后台清理同时检查节点与父 Source 生命周期。
- 停机事务实际将 433 个历史归档节点置为 `retired`，删除 431 个健康队列、431 个健康状态、53115 条归档健康记录和 1350 个已受污染的健康保护窗口；重启后归档 `present` 节点、归档队列及其他非活跃队列均为 0，SQLite 完整性检查为 `ok`，外键错误为 0。
- 离线 `VACUUM` 将 SQLite 主文件从 1123459072 字节压缩到 57348096 字节，空闲页由 250922 页降为 0；数据卷实际占用从 2.4 GiB 降为 168 MiB。按用户要求删除了 1068150784 字节迁移备份和 228315417 字节手工托管备份。
- 新 NAS 镜像 ID 为 `d9c464bd444b30b4b8022b81d76547ce3594a3f1d823c8811ee68bc54b9e10fd`。维护前后 Momo 正式 Artifact ID 均为 `869325ca-350e-42f4-976f-fd7a08530308`，SHA-256 均为 `c00defe32e49d32a3c0fbe450a95702080c4d75750d60d48cc6845d4ca1690ae`，继续发布 201 个节点并明确排除 25 个目标不兼容节点。
- 回归覆盖归档 Source 节点退休、历史归档父级过滤、清理器回收，以及 304/相同 200 内容刷新更新 Source 有效时间但不制造重复 Snapshot；`go test ./...`、`go vet ./...`、本地 Go 构建及固定 Node 镜像中的前端生产构建均通过。

## 仍阻塞公开 Beta

- 使用实际 Momo 配置生成脱敏模板 fixture，并在目标 Momo wrapper/实际内核组合上重复静态校验；正式 Momo 配置保持不变。
- 完成 `linux/arm64` 镜像构建、SBOM、镜像级漏洞扫描和 ARM 实机启动证据；当前已有双架构静态应用构建与 `linux/amd64` NAS 镜像证据。
- 运行时 OpenAPI 继续细化响应 schema；目标 OpenAPI 中尚未实现的修订、回滚、导入导出和管理 API 不得标为完成。
