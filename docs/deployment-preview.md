# ProxyLoom Deployment Preview

> 状态：M4 隔离部署测试，不是公开 Beta 或关键网络生产版本。

## 1. 当前可测试范围

- inline、HTTP、HTTPS Source；远程请求限制为 HTTP(S)、80/443、5 次跳转、每源 1–120 秒超时（默认 30 秒）和最大 50 MiB。
- 单个远程 Source 可独立使用 HTTP、HTTPS、SOCKS5 或 SOCKS5H 拉取代理；代理 URL 和凭据加密保存，管理 API 只返回脱敏代理位置。
- 默认拒绝环回、链路本地、私网和保留地址；单个 Source 可显式设置 `private_network_authorized`。
- 自动识别 sing-box 单节点、outbounds 数组、完整 JSON，Mihomo/Clash YAML，Surge/Loon `[Proxy]`、Quantumult X `[server_local]`，以及 URI/常见 Base64 订阅。
- 远程 Source 可配置加密保存的请求头；拒绝 Host/hop-by-hop 头和控制字符，跨主机或协议重定向删除全部自定义头、Authorization 与 Cookie。
- 完整保存加密 Raw Document、Raw Node、Canonical、Fingerprint 和跨快照 Occurrence。
- `minimum_nodes` 与 `maximum_drop_ratio` 在切换 Snapshot 前执行；失败保留最后有效 Snapshot 和 Artifact。
- 同格式无改名时逐字节输出原输入；同名节点全部保留并使用 `#2`、`#3` 后缀。
- 持久化刷新 Job、租约过期恢复、可选秒级刷新周期、不可变 Artifact 和稳定只读 URL。
- 发布端点支持 ETag、Last-Modified、HEAD 和 304，不在请求线程触发刷新或构建。
- Job/Attempt 诊断不会保存或返回订阅 URL、URL 凭据和远端目标地址。
- Collection 可组合整个 Source 或单个 Node Occurrence，Pipeline 支持过滤、重命名和排序。
- sing-box/Momo Template 只保存无代理节点的完整配置骨架；逻辑出站标签会保留，避免节点重名。
- Output Build 是持久后台任务；Source 刷新和 Collection 更新会自动去重触发，健康过滤边界变化只触发已开启健康过滤的 Output。
- Output 可选择 Momo 1.2.1/sing-box 1.12.25、sing-box 1.12.25 或 sing-box 1.13.14；构建由对应精确版本校验，Source 原样发布不绑定目标版本。
- 管理页面、Argon2id 管理员、HttpOnly Session/CSRF、托管加密备份/恢复和 Key 轮换已接通。

当前尚未实现 Mihomo proxy-provider、目标合同中的全部资源修订/回滚/导入导出 API、镜像 SBOM/签名和 ARM Docker 实机验收。未知协议可同格式无损保存和输出，但只有能力矩阵中标为已实现的协议具备跨格式转换或真实代理检查。跨格式转换遇到没有已验证等价项的字段会拒绝该节点；例如 Hysteria2 URI 的 `pinSHA256` 不能映射为 sing-box 的公钥哈希字段，同格式发布仍会保留原文。

## 2. Docker 首次部署

先构建镜像，再分别初始化数据卷和两个 secret。`init-key`、`init-admin-token` 拒绝覆盖，不能在已初始化环境重复执行。

```bash
docker compose build
docker compose --profile setup run --rm init-data
docker compose --profile setup run --rm init-key
docker compose --profile setup run --rm init-admin-token
docker compose run --rm --no-deps proxyloom bootstrap-token
docker compose up -d proxyloom
docker compose ps
```

保存 `bootstrap-token` 输出中以 `plst1_` 开头的一次性 Setup Token，然后打开 `http://绑定地址:端口/` 创建首个管理员。Setup Token 默认 24 小时过期，初始化成功后立即失效；过期时重新执行同一命令即可，不要清空数据卷或 secret。管理员用户名为 3–64 UTF-8 字节，密码只要求非空且不超过 1024 字节。后续浏览器管理使用 HttpOnly Session，不需要读取 Bearer Token。

默认只绑定 `127.0.0.1:8080`。测试时可显式覆盖：

```bash
PROXYLOOM_BIND=192.0.2.10 PROXYLOOM_PORT=18081 docker compose up -d proxyloom
```

Compose 默认给 ProxyLoom 的独立 bridge 启用 IPv6，并使用 ULA 子网
`fd12:7072:6f78:796c::/64`；Docker 同时自动分配 IPv4 子网。若该 ULA 与宿主已有
网络冲突，可在首次创建网络前覆盖，后续变更需要重建该项目网络：

```bash
PROXYLOOM_IPV6_SUBNET=fd12:3456:789a:1::/64 docker compose up -d proxyloom
```

IPv6 Source 节点的健康检查依赖容器网络具备 IPv6 出站。宿主有 IPv6 默认路由并不
表示 IPv4-only Docker bridge 内的执行器也能访问 IPv6。

HTTPS 反向代理必须显式配置外部 Origin 和 Secure Cookie；服务不会信任未配置的转发头：

```bash
PROXYLOOM_PUBLIC_ORIGIN=https://proxy.example \
PROXYLOOM_SECURE_COOKIE=true \
docker compose up -d proxyloom
```

自动化管理 API 仍可使用独立 256-bit Bearer Token。以下命令会把秘密显示一次到当前终端，不要放入日志或聊天记录：

```bash
ADMIN_TOKEN=$(docker compose run --rm --no-deps proxyloom \
  show-admin-token --path /run/secrets/proxyloom/admin.token | tail -n 1)
```

## 3. 创建测试来源

浏览器打开管理页面，在“订阅管理”中直接填写上游原始 URL 或原始内容。不要先经过 Sub-Store 转换。以下 Bearer 示例只用于自动化测试：

```bash
curl -fsS http://127.0.0.1:8080/api/v1/sources \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{
    "display_name": "URI smoke",
    "type": "inline",
    "content": "vless://one@example.com:443#Hong%20Kong\nvless://two@example.com:443#Hong%20Kong\n",
    "input_format": "auto",
    "output_format": "same",
    "minimum_nodes": 1,
    "maximum_drop_ratio": 0.5
  }'
```

响应为 `202`，包含 `job_id` 和只返回一次的 `subscription_url`。查询任务：

```bash
curl -fsS "http://127.0.0.1:8080/api/v1/jobs/JOB_ID" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

若一次性 URL 丢失，可为已有 Source 新建只读发布令牌；旧令牌不会被自动撤销：

```bash
curl -fsS -X POST "http://127.0.0.1:8080/api/v1/sources/SOURCE_ID/tokens" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

远程来源把 `type` 改为 `remote` 并提供 `url`。只在明确需要访问 NAS 私网地址或私网代理时设置：

```json
{
  "type": "remote",
  "url": "http://10.0.0.10/subscription",
  "private_network_authorized": true,
	"timeout_seconds": 30,
  "refresh_interval_seconds": 3600
}
```

某个上游只能通过 Momo 等 SOCKS 出口访问时，为该 Source 设置独立代理。`socks5h` 让代理端执行最终域名解析，适合本机 DNS 无法取得正确结果的来源；私网代理仍必须显式授权：

```json
{
  "type": "remote",
  "url": "https://example.com/subscription",
  "proxy_url": "socks5h://10.0.0.2:1080",
  "private_network_authorized": true,
  "timeout_seconds": 60,
  "refresh_interval_seconds": 60
}
```

需要认证或专用 User-Agent 时使用 `headers`，不要把账号密码放进 URL userinfo。Header 名和值受数量、长度和 hop-by-hop 安全校验，整个 Source 配置作为加密 Blob 保存：

```json
{
  "type": "remote",
  "url": "https://example.com/subscription",
  "headers": {
    "Authorization": "Basic REDACTED",
    "User-Agent": "Private Client"
  },
  "input_format": "auto",
  "output_format": "same"
}
```

预览版可用完整配置替换现有 Source 并立即创建、发布新修订和刷新 Job；旧 Artifact 在新修订成功前继续服务：

```bash
curl -fsS -X PUT "http://127.0.0.1:8080/api/v1/sources/SOURCE_ID" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data-binary @source-config.json
```

## 4. 聚合输出

1. 在“聚合与规则 > 聚合范围”选择一个或多个 Source。
2. 可选在“节点处理脚本”创建 Pipeline；操作类型为 `filter`、`rename`、`sort`，`schema_version` 固定为 `1`。`filter` 可直接使用 `field`/`operator`/`value`，也可用 `all` 或 `any` 包含 1 到 16 个叶子条件；组合条件不允许继续嵌套。
3. 完整 Momo 模板不得含代理节点，必须在逻辑出站的 `outbounds` 数组内放置 `${PROXYLOOM_NODES}`，或使用 `${PROXYLOOM_NODES_REGEX:<re2>}` 按最终稳定名称分组。
4. 创建 Output 后执行构建。构建 Job 成功才会切换稳定订阅地址；目标校验或内容门禁失败继续提供上一份有效 Artifact。
   包含 Naive 等 1.13 新协议时应选择 `sing-box-1.13.14`；选择 1.12 目标会明确构建失败，不会丢弃节点或回退成不完整配置。
5. Output 订阅地址只在创建或轮换令牌时显示一次。轮换默认立即撤销旧地址。

### 4.1 远程模板

管理页面“聚合与规则 > 规则模板”支持内联 JSON 和远程 URL。GitHub 仓库中的模板应使用 `raw.githubusercontent.com` 原始文件地址；远程内容必须是完整 sing-box 配置、不得自带代理节点，并至少包含一个 ProxyLoom 节点占位符。

```bash
curl -fsS -X POST "http://127.0.0.1:8080/api/v1/templates" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{
    "display_name": "Momo GitHub template",
    "source_type": "remote",
    "target_format": "sing-box",
    "url": "https://raw.githubusercontent.com/OWNER/REPOSITORY/main/config/momo.json",
    "refresh_interval_seconds": 3600
  }'
```

模板创建时立即拉取和校验。之后按周期自动检查；内容 SHA-256 未变化时不增加修订、不重建 Output。新内容校验通过后创建修订并给所有关联 Output 安排去重构建；HTTP、大小、JSON、占位符或引用校验失败时保留最近有效模板与当前 Artifact。

管理员可立即检查一次，不必等待下一周期：

```bash
curl -fsS -X POST "http://127.0.0.1:8080/api/v1/templates/TEMPLATE_ID/refresh" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

刷新周期范围为 60 到 604800 秒。访问 NAS 私网模板时必须对该模板显式启用 `private_network_authorized`；私有 GitHub 仓库可配置请求头，请求头与完整 URL 只保存在加密 Blob 中，管理 API 仅返回脱敏位置。

若局域网 DNS 使用 Mihomo/Momo fake-IP，`raw.githubusercontent.com` 可能只解析到 `198.18.0.0/15` 或 ULA 地址，默认 SSRF 策略会把它视为非公网目的地并拒绝。这种部署必须对该模板显式启用“允许访问私网地址”，或为 ProxyLoom 提供返回真实公网地址的独立 DNS；不要全局关闭 SSRF 检查。

## 5. 运行约束

- Compose 运行用户固定为 `65532:65532`，rootfs 只读，丢弃全部 Linux capabilities，并启用 `no-new-privileges`。
- 数据卷是唯一业务写目录；`master.key` 与 `admin.token` 位于独立只读 secret 卷。
- `/tmp` 是 64 MiB、`noexec,nosuid,nodev` 的 tmpfs。
- 镜像内 1.12.25 用于 Momo/1.12 Output 校验和普通节点健康检查；1.13.14 用于 1.13 Output 校验及 ECH 节点健康检查。没有兼容执行器的节点默认保留。
- `/healthz` 表示进程存活，`/readyz` 表示加密存储、迁移和服务初始化成功。
- HTTP 管理页面只应绑定 loopback 或可信测试网；跨不可信网络必须先配置 HTTPS 反向代理，并按实际部署启用 Secure Cookie。
- `master.key` 与数据卷必须分开备份；丢失任一方都无法恢复加密数据。

## 6. 已验证环境

2026-07-18 早期 M2 预览曾在飞牛 fnOS、Docker Engine 28.5.2、Compose v2.40.3、`linux/amd64` 上完成非 root 启动、健康检查、9 个来源迁移、254 个节点发布和容器重启恢复；一个私有 sing-box 来源的 Artifact 在 Momo 设备实际内核上通过静态校验与隔离 HTTP 204 测试。

同日 M4 镜像在隔离端口 `192.0.2.228:18081` 完成重新验收：原始 sing-box Source 逐字节发布 122 个节点，1.12.25 目标拒绝 Naive 且不发布，1.13.14 目标成功生成完整配置，容器重建后发布哈希与 Artifact ID 保持不变。镜像使用 Go 1.25.12 构建，实际构建环境的 `govulncheck` 可达漏洞为 0。详细证据见 `docs/m4-status.md`。

最终审计又以 Sub-Store 持久化配置中的 9 个原始来源完成回归，当前有效快照为 521 个节点、0 条解析警告，9 个同格式发布端点均为 200。精确排除 25 个使用非等价 `pinSHA256` 的 Hysteria2 URI 后，496 个输入节点生成 498 个出站；另外 6 个 Hysteria2 保留在成功 Artifact 中。后续复测给独立 bridge 启用 IPv6，并修复 Loon `alpn=http1.1` 到 sing-box `http/1.1` 的规范化；当前 189330 字节 Artifact 再次通过 sing-box 1.13.14 校验，当前隔离镜像 ID 为 `023e32019746a68af040e0ca42ea9081541e34b85f9325fdf5a508d842d8dc6b`，未接入 Momo。详细边界和证据见 `docs/m4-status.md`。
