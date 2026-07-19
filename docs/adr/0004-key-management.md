# ADR-0004：主密钥与应用层加密

- 状态：Accepted
- 日期：2026-07-17
- 对应决策：D-002、D-015

## 背景

数据目录包含订阅令牌、节点凭据、原始快照和发布产物。仅设置 SQLite 文件权限不能抵御数据卷离线复制；把主密钥放入同一卷也失去隔离价值。

## 决策

生产容器固定使用 UID/GID `65532:65532`。`proxyloom init-key` 创建数据卷外的常规文件，格式为 `plmk1:<uuid-key-id>:<32-byte-base64url>` 加换行。命令使用排他创建，拒绝符号链接及已有路径，最终属主 `65532:65532`、模式 `0600`。运行容器把 secret 目录只读挂载到 `/run/secrets/proxyloom/`，活动文件固定为 `master.key`。

采用信封加密：

- Master Key 仅包装随机 Data Encryption Key，不直接加密业务对象。
- `fingerprint-hmac`、`health-hmac`、`token-hmac` 使用相互独立的 256 bit Key。
- 数据库敏感字段和 Blob 使用按用途分离的 AES-256-GCM DEK；每个密文使用随机 96 bit nonce。
- AAD 固定包含实例 ID、表/Blob 类型、记录 ID、字段名和密文格式版本，防止密文跨位置替换。
- 密文信封记录 `format_version`、`key_id`、`nonce` 和 ciphertext；DEK 包装记录独立版本。

Master Key 轮换使用可崩溃恢复的双 wrapping：

1. 初始化服务在同一 secret 目录排他创建 `master.key.next`；运行服务通过只读目录挂载以 `O_NOFOLLOW` 打开该文件，经过认证的本机 CLI 只触发准备动作，不通过 API、argv 或环境传递 Key 材料。
2. 服务在一个事务中创建 `prepared` Master Key Slot，并为全部未退役 Data Key 增加新 wrapping，旧 wrapping 保留。
3. 初始化服务将当前文件保留为 `master.key.previous`，再在同一文件系统原子 rename `master.key.next` 为 `master.key`；运行容器因挂载目录而非单文件可观察新 inode。
4. 服务或重启恢复逻辑按文件中的 Key ID 验证 prepared wrapping，事务性切换 active slot；确认后才允许清理 previous 文件和旧 wrapping。

崩溃在步骤 2 前可直接丢弃 next；步骤 2 后、rename 前仍由旧 Key 启动；rename 后、active 切换前由新文件匹配 prepared slot 并完成切换。HMAC Key 本身不变。数据 DEK 轮换另采用新写使用新 Key、后台重加密旧记录、完成后退役旧 Key。未知文件 Key ID、无对应完整 wrapping、AEAD 验证失败时 readiness 失败，不能返回空数据。

管理员密码使用 Argon2id；M0 基线为 64 MiB、3 次迭代、并行度 1、16 字节随机 salt、32 字节输出，启动时可根据参考设备只向更高成本调整。会话和发布令牌只保存独立 Key 的 HMAC 摘要。

## 后果

- 直接冷备份数据卷时，`master.key` 必须分开备份且只有一者无法恢复秘密数据；应用生成的自包含托管备份按独立备份 Key 规则处理，不依赖复制原 Master Key。
- 数据卷离线复制不会直接暴露敏感字段，但正在运行的已授权主机仍在信任边界内。
- SQLite 的索引列只能保存非敏感派生值或带密钥摘要，不能保存明文服务器凭据。
- 托管备份使用独立口令或接收方公钥进行自包含逻辑加密，不能把可直接挂载的 Master Key 文件塞进备份包。
