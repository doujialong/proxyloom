# ProxyLoom

Lossless, health-aware proxy subscription manager.

ProxyLoom 是一个面向个人、家庭和小型自托管环境的代理订阅管理器。项目优先保证同格式节点无损输出、稳定保留重复节点、分离订阅源与节点健康状态，并以明确的六维能力矩阵持续扩展协议支持。

## 当前阶段

项目已形成可部署测试的 M4 纵向闭环：加密 Source/Snapshot/Raw Node、同格式无损发布、跨格式 sing-box 转换、真实健康检查、Collection/Pipeline/Template/Output 聚合、稳定命名、后台自动重建、管理员 Session/CSRF、托管备份恢复、Key 轮换和 Vue 管理端均已接通。管理端以实际操作为主，支持订阅增改归档、节点健康与复测、聚合范围、远程规则模板、节点处理脚本、输出策略、密码修改和内置使用说明。当前适合隔离的 NAS 验收，尚未达到公开 Beta 或关键网络生产准入。

- 产品规范：[REQUIREMENTS.md](./REQUIREMENTS.md)
- M0 准入检查：[docs/m0-checklist.md](./docs/m0-checklist.md)
- M1 实现状态：[docs/m1-status.md](./docs/m1-status.md)
- M1 出口审计：[docs/M1-EXIT-AUDIT.md](./docs/M1-EXIT-AUDIT.md)
- M2 实现状态：[docs/m2-status.md](./docs/m2-status.md)
- M4 部署测试状态：[docs/m4-status.md](./docs/m4-status.md)
- 部署测试说明：[docs/deployment-preview.md](./docs/deployment-preview.md)
- 系统架构：[docs/architecture.md](./docs/architecture.md)
- 当前运行时 OpenAPI：[api/openapi-runtime.yaml](./api/openapi-runtime.yaml)
- 完整目标 OpenAPI：[api/openapi.yaml](./api/openapi.yaml)
- SQLite Schema 草案：[db/schema.sql](./db/schema.sql)
- 协议能力矩阵：[docs/protocol-matrix.yaml](./docs/protocol-matrix.yaml)
- 格式与协议适配器契约：[docs/adapter-contract.md](./docs/adapter-contract.md)

## 已冻结基线

- P0 目标：Momo v1.2.1 + sing-box v1.12.25，以及独立的上游 sing-box v1.12.25；Momo 官方仓库、Release、标签提交和 x86_64/OpenWrt 25.12 发布资产摘要均已锁定。
- 首个兼容性目标：sing-box v1.13.14；容器同时固定 1.12.25 与 1.13.14，Output 按 Target Profile 使用对应二进制校验并记录实际版本。
- 后续 Mihomo 研究基线：v1.19.28。
- 后端：Go；存储：SQLite；前端：Vue 3 + TypeScript，构建产物由 Go 服务同源内嵌。
- 部署：单服务容器、一个加密数据目录、独立只读 `master.key`。
- 许可证：AGPL-3.0-or-later。

## 已验证纵向链路

- 严格有界的 sing-box JSON 解析；对象顺序、字符串转义和数字词法由有序 AST 保留，重复键稳定拒绝。
- sing-box 完整配置/出站数组识别，代理节点、逻辑出站、已移除类型和未知类型分离。
- 格式无关的 HMAC-SHA-256 投影接口、`occurrence-v1`、30 天缺席恢复与 `name-suffix-v2` 稳定编号。
- 只修改 `/tag` 的最小 Patch，以及确定性 `outbounds` Artifact。
- AC-001、AC-002、AC-003、AC-009、AC-015、AC-019、AC-023 的 M1 范围已有自动化证据。
- Collection 可混合 Source 与单个 Node Occurrence；Pipeline 支持过滤、重命名和排序。
- Momo/sing-box 完整模板支持全节点和正则节点占位符；模板逻辑出站标签参与稳定名称保留。
- 完整模板可从 GitHub Raw 或其他 HTTP(S) URL 加密缓存，支持定时/手工刷新；仅在新内容校验通过且摘要变化后创建修订并重建关联 Output，失败继续使用上一份有效模板。
- 来源刷新、集合更新和健康过滤边界变化会生成去重、可恢复的后台 Output Build Job。
- Source 同格式发布只做内部结构校验，不受某个固定目标内核限制；外部 `sing-box check` 只在声明了精确 Target Profile 的 Output 构建阶段执行。
- 构建内容门禁或目标校验失败不会切换最后有效 Artifact，也不会残留未引用的构建 Blob。

源码仓库为 [`doujialong/proxyloom`](https://github.com/doujialong/proxyloom)，计划使用 `ghcr.io/doujialong/proxyloom` 发布容器镜像。当前版本仍是部署预览，不代表公开 Beta 或生产准入。

## Deployment Preview

当前容器支持直接导入 inline 或 HTTP/HTTPS 原始来源，单个远程来源可独立配置 HTTP、HTTPS、SOCKS5 或 SOCKS5H 拉取代理和 1–120 秒超时。系统自动识别 sing-box JSON、Mihomo/Clash YAML、Surge/Loon/Quantumult X 原生文本与 URI/Base64 列表，并加密保存认证/自定义请求头及代理凭据。同格式且无需改名时，Artifact 直接复用原输入字节；同名节点全部保留，并稳定追加 `#2`、`#3` 数字后缀。未知合法协议同格式原样保留，不因健康执行器尚不支持而删除。

```bash
docker compose build
docker compose --profile setup run --rm init-data
docker compose --profile setup run --rm init-key
docker compose --profile setup run --rm init-admin-token
docker compose run --rm --no-deps proxyloom bootstrap-token
docker compose up -d proxyloom
```

`bootstrap-token` 会输出以 `plst1_` 开头、默认 24 小时有效的一次性管理员 Setup Token。服务启动后打开 `http://NAS地址:端口/`，页面会显示同一条令牌生成命令并引导完成管理员注册；令牌过期时重新生成即可。登录后可从“使用说明”完成首次订阅、聚合和输出，也可参考 [docs/deployment-preview.md](./docs/deployment-preview.md) 了解 secret 备份和安全边界。

## 设计约束

1. 原始节点是无损事实来源，标准化节点只是可查询、可转换的派生视图。
2. 自动流程不因名称或连接指纹相同而合并节点。
3. 同格式输出只在原对象上应用声明过的最小补丁。
4. 构建失败或健康基础设施异常不能覆盖最后有效产物。
5. “支持协议”必须逐项声明识别、无损直通、标准化、转换、真实健康检查和目标校验能力。

## 参与和安全

- 贡献说明：[CONTRIBUTING.md](./CONTRIBUTING.md)
- 安全报告：[SECURITY.md](./SECURITY.md)
- 变更记录：[CHANGELOG.md](./CHANGELOG.md)

## 许可证

Copyright (C) 2026 ProxyLoom contributors.

本项目计划以 GNU Affero General Public License v3.0 or later 发布，详见 [LICENSE](./LICENSE)。第三方执行器和依赖分别遵守各自许可证。
