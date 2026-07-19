# ProxyLoom 格式与协议适配器契约

> 状态：M1 Baseline
>
> 日期：2026-07-18
>
> 规范来源：[REQUIREMENTS.md](../REQUIREMENTS.md)、[protocol-matrix.yaml](./protocol-matrix.yaml)

## 1. 目标

sing-box 是首个实现和验证的参考适配器，不是 ProxyLoom 的协议或格式边界。核心域不得依据 sing-box 字段、协议名称或当前已有 fixture 做分支。新增 URI、Mihomo 或客户端专有格式时，应新增适配器和能力证据，而不是改写 Occurrence、命名、HMAC 或 Raw Node 的基本语义。

## 2. 分层契约

| 层 | 必须提供 | 不得承担 |
| --- | --- | --- |
| Format Adapter | 格式检测、有界解析、Raw Node 切分、原始类型、显示名称路径、同格式最小补丁与无损编码 | 猜测未知协议语义、用 Canonical 重建同格式 Raw Node |
| Protocol Adapter | 稳定协议 ID、来源格式字段映射、Canonical 派生视图、连接身份投影、协议字段校验 | 删除 Raw 字段、把未验证目标标为支持 |
| Target Adapter | 客户端/内核精确版本、可表达字段、渲染、降级报告和目标校验 | 用“同为 JSON/YAML”代替客户端兼容证据 |
| Executor Adapter | 真实协议栈、最小临时配置、探测结果和资源边界 | 把 TCP 端口连通当作真实代理健康 |

注册键必须是 `(format_id, raw_type)`，不能只按 `raw_type`。同一个 `vless`、`ss` 或 `http` 名称在 sing-box、Mihomo、URI 和客户端扩展中可以有不同字段语义与适配版本。

## 3. 通用核心输入

- Identity 只接收适配器产生的版本化投影、投影种类和排除规则，不依赖具体协议包。
- Occurrence 只依赖 Fingerprint、来源内路径、协议 ID、原始名称和显式时间/ID 生成器。
- Name Allocation 只依赖 Occurrence ID、基础名、稳定键、保留期和目标内保留名称。
- 同格式 Build 必须从 Raw Node 深拷贝应用白名单 Patch；跨格式 Build 才能消费 Canonical View。
- 所有运行时能力按能力矩阵六个维度独立发布，不能因为某格式可识别就推导其他格式可转换或可健康检查。

## 4. 未知与新增协议

1. 结构化格式先完成 Raw Node 切分、显示字段规则和不透明结构指纹，使未知协议可以同格式无损直通。
2. 获得公开规范、主流上游实现或合法脱敏 fixture 后，注册格式专属原始类型映射。
3. 补充 Canonical 与连接身份投影；适配器必须声明所覆盖的认证、TLS、ECH、Reality、传输和扩展字段。
4. 分别补齐渲染、真实协议探测和精确目标版本校验；缺少任一证据时对应维度保持 `partial|not_implemented|blocked`。
5. 新稳定版出现字段时先验证 Raw 无损，再决定身份投影和 Canonical 版本是否升级；不得静默改变既有 Fingerprint。

## 5. 格式扩展顺序

| 格式族 | 当前状态 | 下一证据 |
| --- | --- | --- |
| sing-box JSON | M1 首个参考适配器 | 完整配置合并与 Momo/sing-box 目标二进制校验 |
| URI/Base64 订阅 | M2 原始格式适配器已实现 | 继续补齐逐协议 Canonical、字段校验、编辑与跨格式渲染 fixture |
| Mihomo YAML/JSON | M2 YAML 原始格式适配器已实现 | proxy-provider、逐协议 Canonical、跨格式渲染和 v1.19.28 目标二进制 fixture |
| Surge/Loon/Quantumult X | M2 原始文本适配器已实现 | 更多公开 fixture、逐协议 Canonical、完整客户端校验与跨格式渲染 |
| Shadowrocket 及其他客户端格式 | 研究清单 | 合法公开样本、格式语法和目标能力边界 |

这张顺序表只决定实现先后，不缩减“所有公开且可合法互操作协议”的持续覆盖范围。

## 6. 准入测试

每个新适配器至少需要：检测 fixture、恶意输入与资源上限测试、未知协议无损 golden、协议级 Canonical fixture、身份正反变形测试、同格式最小 Patch 测试、确定性重放，以及能力矩阵证据路径检查。渲染、真实健康和目标校验只有在对应 fixture 或实际二进制测试通过后才能升级状态。
