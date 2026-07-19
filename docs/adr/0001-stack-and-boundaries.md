# ADR-0001：技术栈与进程边界

- 状态：Accepted
- 日期：2026-07-17
- 对应决策：D-004、D-014、D-016

## 背景

ProxyLoom 需要在 2 vCPU、2 GiB 内存的 NAS/VPS 上运行，同时处理不可信订阅、持久化任务、无损构建和真实代理探测。核心领域逻辑不能被 HTTP 框架、数据库表示或某个代理内核绑死。

## 决策

采用 Go 后端、SQLite、Vue 3 + TypeScript。生产镜像只运行一个 ProxyLoom 服务进程；前端静态资源嵌入该服务。真实代理探测由受监管的 sing-box 子进程执行，不形成第二个常驻服务。

源码模块按以下依赖方向组织：

```text
HTTP / Scheduler / CLI
          |
          v
   Application services
          |
          v
 Domain model and policies
    |        |         |
    v        v         v
Storage   Adapters   Executors
```

- `domain` 不导入 HTTP、SQLite、sing-box 或前端类型。
- `application` 负责用例、事务边界、权限和任务编排。
- `storage/sqlite` 实现仓储、迁移、租约和原子发布。
- `adapter` 实现格式检测、解析、指纹投影、渲染和目标校验。
- `executor` 以版本化进程协议管理 sing-box/Mihomo 等外部工具。
- `api` 和 Web UI 只使用公开应用契约，不直接查询数据库。

单实例是 v1.0 的部署边界。SQLite 写租约和进程级文件锁共同拒绝第二个活动实例；不会在 M0 假设未来可横向扩展。

## 后果

- 单镜像部署简单，已构建发布端点不依赖外部内核常驻。
- 外部执行器崩溃不会直接破坏主进程内存，但仍必须施加进程、文件描述符、内存和超时限制。
- 跨进程探测有额外开销，因此执行器池与探测并发必须分开建模。
- 若未来支持多实例，需要替换任务租约、当前产物切换和 SQLite 写模型，属于新的 ADR。
