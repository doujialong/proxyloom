# ProxyLoom M0 安全与加密设计

> 状态：M0 Baseline
>
> 对应需求：SEC-000 至 SEC-004

## 1. 保护目标与边界

保护目标是：订阅和节点秘密不因数据库、日志、临时文件、API 或备份泄露；恶意内容不能访问未授权网络或耗尽服务；未授权浏览器/局域网用户不能操作管理端；错误密钥、验证失败和批量网络异常不能发布空或损坏结果。

P0 不防御已经取得运行容器 root、宿主 root 或管理员会话的攻击者，也不提供多租户隔离。数据卷离线复制在没有 Master Key 时应无法恢复秘密；Master Key 与数据卷同时泄露超出该边界。

## 2. 数据分类

| 等级 | 示例 | 存储/展示 |
| --- | --- | --- |
| Secret | 管理密码、会话/发布令牌明文、Master Key、节点密码/私钥 | 明文只在必要内存；密码哈希、令牌 HMAC、其余 AEAD |
| Sensitive | 订阅 URL、Header、Raw Document、Canonical Node、Artifact、服务器地址 | 数据目录中 AEAD；UI/API 默认遮罩 |
| Internal | 资源名、策略、健康错误、审计差异 | 数据库；错误与日志脱敏 |
| Public | 版本、协议矩阵、健康端点布尔状态 | 可公开，仍不包含实例秘密 |

节点秘密查看、秘密配置导出、备份创建/下载、主密钥轮换和新发布令牌明文生成需要最近 5 分钟内重新认证，响应设置 `Cache-Control: no-store`，事件写安全审计。诊断包默认只含 Public/Internal 脱敏数据。

## 3. 密钥体系

Master Key 格式、UID/GID 和轮换见 [ADR-0004](./adr/0004-key-management.md)。启动顺序为：

1. 以 `O_NOFOLLOW` 打开常规文件，校验属主 `65532:65532`、模式不宽于 `0600`、格式与 32 字节长度。
2. 打开 SQLite，只读取 schema metadata、文件 Key ID 对应的 Master Key Slot 和 wrapping；若文件匹配完整的 `prepared` slot，按 ADR-0004 完成恢复切换。
3. 解包全部 active/decrypt-only Data Key，并用该 Master Key Slot 的固定 canary AEAD 验证 Key。
4. 验证模式、Blob 根目录和当前 Artifact 引用。
5. 成功后才把 readiness 置为 true 并注册管理/发布路由。

密文格式：

```text
version = 1
algorithm = AES-256-GCM
key_id = UUIDv7
nonce = 12 random bytes
aad = "proxyloom\0v1\0<instance>\0<kind>\0<record>\0<field>"
ciphertext = seal(plaintext, aad)
```

Nonce 由 CSPRNG 生成，不使用计数器。加密和数据库写入作为一个应用事务；失败的外部 Blob 不进入引用表。解密错误返回稳定内部错误 `crypto_integrity_failed`，日志只带 record ID/correlation ID。

HMAC 用途 Key 分离：Fingerprint、Health Key、Token、Sensitive Content Digest。禁止把一个摘要跨用途比较。Token 验证先按公开 token ID 找候选，再常量时间比较 HMAC；数据库不保存 token 明文。

## 4. 认证与浏览器安全

- 首个管理员不能由任意网络访问者抢注。管理员在本机运行 `proxyloom bootstrap-token` 获取一次性 256 bit 令牌；服务只保存 HMAC，令牌默认 24 小时过期且成功使用后立即作废。初始化 API 必须同时携带该令牌。令牌过期时可直接重新生成，不需要清空数据库或 secret。
- 管理员密码采用 ADR-0004 的 Argon2id 下限；登录错误统一返回 `invalid_credentials`。
- Cookie 会话使用 256 bit 随机值、`HttpOnly`、`SameSite=Lax`、Path `/`；HTTPS 部署设置 `Secure`。
- 有副作用请求必须同时满足 SameSite、Origin/Referer 精确检查和双提交/服务器会话绑定的 CSRF token；Bearer 管理令牌不使用 Cookie，但仍受 CORS 限制。
- CORS 默认关闭。允许时只接受配置的 `https://host[:port]` 精确来源，不允许通配符与凭据组合。
- 登录按客户端网络与账号标识双层限速；恢复命令使全部会话失效。
- `If-Match`、权限和 CSRF 校验发生在读取/解密请求正文秘密之前。

反向代理头只在直接连接 IP 属于配置 CIDR 时信任。未受信来源的 `Forwarded`、`X-Forwarded-*` 被忽略。生产公网部署必须由反向代理或服务端 TLS 提供 HTTPS。

## 5. SSRF 与解析限制

远程抓取只允许 `http`/`https`，默认端口 80/443，可配置的额外端口也受全局允许列表约束。每次请求和跳转：

1. 解析规范 URL，拒绝 userinfo、空主机、混淆 IP、非允许 scheme。
2. 解析全部 A/AAAA，过滤未获资源授权的环回、链路本地、私网、组播和保留地址；至少存在一个获准地址才可继续，拨号不回退到被过滤地址。
3. 连接固定到已验证 IP，但 TLS SNI/Host 保持原主机；响应后不复用到未经验证的新主机。
4. 最多 5 次跳转；跨主机删除 Authorization、Cookie 和标记为 secret 的自定义 Header。
5. 限制连接/总超时、压缩后与解压后大小、读取速率和响应 Header 大小。

JSON 限制最大深度 64、单字符串 1 MiB、默认响应 10 MiB、默认 AST 值数 1,000,000、默认节点 20,000；全局硬上限分别为 128、4 MiB、50 MiB、5,000,000 个 AST 值和 100,000 个节点。YAML 禁止自定义 tag/对象实例化，别名展开节点计数进入相同硬上限。Base64 在解码前后分别限制大小。

私网授权按单个 Source/Template Revision 保存，预览明确列出目标网段；它不自动授权节点健康探测。Probe Profile 使用单独目标允许列表，避免构成扫描器。

fake-IP DNS 可能把公网域名只映射到 `198.18.0.0/15` 或 ULA。系统不得静默把这些网段视为公网；资源必须显式授权，或部署独立返回真实公网地址的 DNS。混合答案中若同时存在公开地址与未授权 fake/private 地址，只固定拨号到公开候选。

## 6. 外部执行器隔离

- 固定可执行文件路径与发布摘要，不从订阅或 PATH 选择二进制。
- 子进程使用 UID/GID 65532、独立进程组、最小环境、关闭继承文件描述符。
- 只写受限 tmpfs；临时文件 `0600`，随机名，任务结束和启动恢复时清理。
- Linux 生产镜像设置 no-new-privileges、drop all capabilities、只读 rootfs；Compose 对 tmpfs 设置 `noexec,nosuid,nodev` 和大小上限。
- 子进程限制 wall time、进程数、打开文件、配置大小和输出大小；stdout/stderr 超限截断并脱敏。
- 临时代理只绑定容器内 loopback 随机端口，Supervisor 建立后立即探测，结束时杀死整个进程组。
- 节点秘密通过权限受限 stdin 或临时文件传入，不出现在 argv、环境或日志。

执行器错误分为节点错误和基础设施错误。崩溃、配置生成错误、资源限制和控制探测失败不得增加节点认证失败计数。

## 7. 发布端点与秘密最小化

发布 token 至少 32 随机字节，只绑定一个 Output 和 `read:artifact`。URL 日志中完整路径 token 被替换为 token ID 前 8 位；Referer Policy 为 `no-referrer`。响应带 `X-Content-Type-Options: nosniff`、`Cache-Control: private, no-cache`。

公共探测请求不携带 ProxyLoom/节点/来源标识、Cookie、Authorization 或唯一请求 ID，使用固定通用 User-Agent。UI 告知探测服务可看到出口 IP。默认两个代理探测目标，用户可全部替换为自建目标。

## 8. 备份、恢复与轮换

- 一致性托管备份先固定 SQLite 读取点与引用 Blob 清单，再把逻辑记录流式写入备份容器，最后认证 manifest 和摘要；口令模式使用独立 Argon2id 派生 Key，公钥模式使用随机文件 Key 的接收方封装。
- 恢复预检在受限 tmpfs 中流式验证容器、版本、AEAD、摘要和引用，并把逻辑内容重新加密到目标实例的有期限 staging Blob；错误口令或损坏输入不留下部分资源。
- 正式恢复先自动创建当前实例的托管备份，再消费 digest 匹配且未过期的 staging 记录并原子切换。完整恢复保留备份中的 logical instance ID 后重建目标实例密文；配置导入则使用当前 instance ID。两者都不得忽略 AAD。
- 直接复制数据目录的冷备份不执行逻辑导出，必须与原 `master.key` 分开保存且恢复时两者缺一不可。
- Token、Master Key、DEK 轮换都写审计；中途失败保持旧 Key 可读和新 Key 状态可恢复。

## 9. 审计与日志

审计记录保存 UTC 时间、actor、动作、资源、结果、IP（按隐私策略）、correlation ID 和脱敏 diff。秘密值统一替换为 `***`，URL 只保留 scheme/host/path 模板。普通管理员不能无痕删除审计；清理动作本身写入独立保留事件。

日志结构化字段使用允许列表，禁止直接序列化请求、节点、外部进程配置或错误对象。CI 使用固定 canary secrets 贯穿导入、构建、健康、备份和错误路径并扫描所有输出。

## 10. 威胁与控制矩阵

| 威胁 | 主要控制 | 验证 |
| --- | --- | --- |
| 数据卷离线复制 | AEAD + 卷外 Master Key | 错误/缺失 Key 启动测试 |
| 恶意订阅 SSRF/rebinding | 每跳解析与固定 IP、私网授权 | 重定向和 DNS 切换测试 |
| 解析炸弹 | 深度、大小、别名、节点硬上限 | AC-013 fixture |
| CSRF/CORS | SameSite、Origin、CSRF token、精确 CORS | 浏览器集成测试 |
| 发布令牌泄漏 | HMAC 存储、日志遮罩、轮换 | canary 扫描与吊销测试 |
| 子进程泄密/失控 | argv 禁密、tmpfs、配额、进程组 | 崩溃/超时/输出洪泛测试 |
| 健康站点大面积失败 | 双目标控制探测、批次熔断 | 故障注入测试 |
| 旧构建覆盖新构建 | 固定修订、CAS 发布序号 | AC-011 并发测试 |
| 密文替换/损坏 | AAD + AEAD + readiness 安全失败 | 记录交换和 bit flip 测试 |

## 11. 发布前仍需执行的验证

M0 固定设计但不证明实现安全。进入公开 Beta 前必须完成认证绕过、CSRF、CORS、SSRF、路径穿越、秘密扫描、依赖漏洞、容器权限、备份恢复和密钥轮换测试；任何 Critical 漏洞阻止发布。
