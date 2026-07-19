# ProxyLoom API v1 约定与错误码

> 状态：M0 Baseline
>
> 机器契约：[openapi.yaml](../api/openapi.yaml)

## 1. 版本与表示

管理 API 从 `/api/v1` 开始。v1 内只允许向后兼容地新增可选字段、端点和枚举能力；客户端必须容忍未知响应字段，但不能假设未知枚举可执行。破坏性变更使用 `/api/v2` 并提供迁移期。

JSON 使用 UTF-8。时间为带时区 RFC 3339，服务端输出 UTC `Z`。ID 是小写 UUIDv7，令牌和游标是不可解析的 opaque string。秘密请求字段标记 `writeOnly`；只展示一次的响应秘密标记 `readOnly` 并使用 `Cache-Control: no-store`，普通详情响应只返回遮罩值或 hint。

## 2. 分页与排序

列表默认 50、最大 200。每个端点声明稳定排序，最后以 ID 兜底。游标包含排序键、过滤摘要、签发/过期时间并由 Token HMAC Key 签名，有效期 15 分钟；修改 filter、sort 或 limit 后不得复用旧游标。

游标不是数据库快照。翻页期间新增或更新记录可能出现在后续刷新中，但稳定键集分页不得因相同排序值重复/跳过既有记录。无效、过期或签名错误统一返回 `cursor_invalid`，不透露内部内容。

## 3. ETag 与并发

Revisioned Resource 的强 ETag 由资源 ID、revision counter 和当前 draft/published Revision ID 计算。PATCH、发布和归档必须带 `If-Match`。不匹配返回 412 `precondition_failed`，details 可以包含当前 ETag 和 Revision ID，但不包含秘密 diff。

业务状态冲突使用 409，例如归档资源仍尝试发布；字段/引用不合法使用 422。客户端不能用最后写入覆盖解决修订冲突，应重新读取并比较。

## 4. 幂等与后台任务

刷新、检查、构建、导入、备份、恢复和回滚必须带 `Idempotency-Key`。作用域为 actor + HTTP method + 规范 path，服务保存 Key HMAC、规范请求摘要和原响应 24 小时：

- 相同 Key 与相同请求返回原 Job/响应，不创建第二个任务。
- 相同 Key 与不同请求返回 409 `idempotency_key_reused`。
- 24 小时后可以作为新请求使用，但客户端应使用新随机 Key。

长操作返回 202、`Location: /api/v1/jobs/{id}` 和 JobReference。客户端断开不取消任务。只有 queued Job 及明确支持协作取消的 running Job 可取消；Artifact 原子提交、恢复切换和 Key 轮换提交阶段不可取消。

配置导入、名称压缩和恢复采用“预检 ID + 预检 digest + 明文确认词”三元组，预检默认 15 分钟过期且只能消费一次。上传使用受限流式 multipart，不把 50 MiB/1 GiB 文档编码成 JSON 字符串；恢复预检只保存由目标实例重新加密的 staging Blob。

## 5. 错误格式

所有管理错误使用：

```json
{
  "error": {
    "code": "validation_failed",
    "message": "请求包含无效字段",
    "correlation_id": "01...",
    "details": [
      {"field": "/policy/timeout_seconds", "code": "out_of_range", "message": "必须在 1 到 120 之间"}
    ]
  }
}
```

`message` 可以本地化，客户端逻辑只能使用 `code` 和 detail `code`。correlation ID 可公开用于查日志，不含资源秘密。

## 6. v1 稳定错误码

| HTTP | code | 含义 |
| ---: | --- | --- |
| 400 | `request_invalid` | JSON、参数、filter 或 sort 语法错误 |
| 400 | `cursor_invalid` | 游标无效、过期或与查询不匹配 |
| 401 | `authentication_required` | 缺少或失效管理凭据 |
| 401 | `invalid_credentials` | 登录失败，不区分账号与密码 |
| 401 | `publication_token_invalid` | 发布令牌无效或已吊销 |
| 403 | `permission_denied` | 主体没有所需 scope |
| 403 | `csrf_invalid` | Cookie 请求缺少或使用错误 CSRF token |
| 403 | `recent_authentication_required` | 查看秘密前需要重新认证 |
| 409 | `resource_state_conflict` | 当前生命周期不允许操作 |
| 409 | `idempotency_key_reused` | 相同幂等键对应不同请求 |
| 409 | `name_lock_conflict` | 锁定名称在 Output 内冲突 |
| 409 | `job_not_cancellable` | Job 已进入不可取消阶段 |
| 409 | `preview_digest_mismatch` | 预检 ID、输入摘要或资源修订已变化 |
| 409 | `preview_expired_or_consumed` | 预检已过期或已被使用 |
| 412 | `precondition_failed` | `If-Match` 已过期 |
| 413 | `payload_limit_exceeded` | 原文、解压、解码或展开后超过硬上限 |
| 422 | `validation_failed` | 字段、引用或资源语义不合法 |
| 422 | `format_ambiguous` | 无法唯一判断格式，需要用户指定 |
| 422 | `json_duplicate_key` | 结构化 JSON 包含语义不确定的重复对象键 |
| 422 | `lossy_conversion_not_allowed` | 目标无法表达关键字段且未授权降级 |
| 422 | `target_validation_failed` | 目标 Profile 验证失败 |
| 422 | `snapshot_gate_failed` | 新内容未通过来源有效性门槛 |
| 422 | `publication_gate_failed` | 节点数量/降幅安全门槛阻止发布 |
| 429 | `rate_limited` | 登录或高成本动作限速 |
| 503 | `service_not_ready` | 初始化、Key、迁移或存储阻止服务 |
| 503 | `health_infrastructure_degraded` | 探测基础设施熔断，未摘除节点 |
| 500 | `crypto_integrity_failed` | AEAD/Key 完整性失败；服务同时退出 ready |
| 500 | `data_integrity_failed` | 不变量、引用或重放输入损坏 |
| 500 | `internal_error` | 未分类错误，响应不含堆栈或秘密 |

来源抓取、解析和执行器的细粒度失败码主要属于 RefreshAttempt/HealthRecord 数据，不都映射成同步 HTTP 错误。后台 Job 的 `error.code` 复用同一命名规则。

## 7. 安全约定

- Cookie 写请求需要 CSRF token；Bearer 请求不需要 CSRF，但仍受精确 CORS 策略。
- 首次管理员初始化必须带本地生成的一次性 Setup Token。
- 发布 URL 的 path token 在访问日志、错误和 Referer 中遮罩。
- 节点秘密、秘密配置导出、备份创建/下载和新发布令牌要求当前会话在 5 分钟内重新认证；`POST /api/v1/session/reauthenticate` 只延长当前会话窗口。
- 响应秘密明文使用 `Cache-Control: no-store`，只展示一次的 token 不可通过 GET 再取。
- 429 提供合理的 `Retry-After`；认证错误的时间和文案不区分账号是否存在。
