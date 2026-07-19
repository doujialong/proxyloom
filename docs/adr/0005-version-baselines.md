# ADR-0005：M0 版本与兼容范围

- 状态：Accepted
- 日期：2026-07-17
- 对应决策：D-009、D-010、D-020、D-021

## 决策

M0 冻结以下版本：

| 标识 | 精确版本 | 阶段 | 用途 |
| --- | --- | --- | --- |
| `momo-singbox-1.12` | Momo v1.2.1 + sing-box v1.12.25 | P0 | Momo 组合目标配置、wrapper fixture 与精确内核校验 |
| `singbox-1.12` | sing-box v1.12.25 | P0 | 原生输入、输出、验证及健康执行器 |
| `singbox-1.13` | sing-box v1.13.14 | 首个兼容性版本 | 验证适配层可跟随稳定版本 |
| `mihomo-1.19` | Mihomo v1.19.28 | P1 研究基线 | M5 输入输出和执行器设计，不进入 P0 |

版本字符串指上游正式发布标签，不允许使用浮动的 `latest`。CI fixture、目标验证器、镜像内二进制、许可证清单和构建清单必须记录精确版本及 SHA-256。

2026-07-17 源码标签解析结果：sing-box v1.12.25 为 commit `73bfb99ebce7923c485435e4faf8571b412065a9`，v1.13.14 为 `25a600db24f7680ad9806ce5427bd0ab8afe1114`，Mihomo v1.19.28 为 `cbd11db1e13a75d8e680e0fe7742c95be4cba2be`。

2026-07-18 镜像固定的官方 Linux 资产 SHA-256：v1.12.25 amd64 `a1ec76e2b6b139eb747a1b1ebee7d14b8d4be5a833596cad8070a31ef960301f`、arm64 `719b76196c8b31efa636b2d8f669e314547e0da0a5ab38a75e1882d307bbd154`；v1.13.14 amd64 `f48703461a15476951ac4967cdad339d986f4b8096b4eb3ff0829a500502d697`、arm64 `4742df6a4314e8ecc41736849fca6d73b8f9e91b6e8b06ee794ff17ba180579e`。

2026-07-18 已确认 Momo 官方仓库为 `https://github.com/nikkinikki-org/OpenWrt-momo`，v1.2.1 Release 为 `https://github.com/nikkinikki-org/OpenWrt-momo/releases/tag/v1.2.1`，轻量标签解析到 commit `dc0b315030aff15687829e3c411421299d32298a`。该标签的 LuCI 版本为 `1.2.1`、包版本为 `2026.06.03-r1`，包声明许可证为 GPL-3.0+，README 声明依赖 sing-box >= 1.12。用于 x86_64/OpenWrt 25.12 fixture 的官方资产 `momo_x86_64-openwrt-25.12.tar.gz` SHA-256 为 `63646cbe147f4260cdc21fc69176e8f7100ca41a9d79a07b6a4c2f2ff4493394`。`source_verification` 因而设为 verified；这只确认来源身份，不代表 M4 目标校验已经实现。

同日对用户参考设备进行脱敏只读核查：实际安装的是 `momo-2025.12.31-r1` / `luci-app-momo-1.1.0-r1`，关键文件与官方 v1.1.0 commit `ce1d6a9c17b137ad3ff726008aff0a07a746fd49` 完全匹配；APK 数据库登记 `sing-box-1.12.15-r1`，实际二进制则为定制 `sing-box 1.13.14-urltestfix.4256`，Revision `25a600db24f7680ad9806ce5427bd0ab8afe1114`。服务处于 running，当前配置通过 `sing-box check`。该观察证明 Momo wrapper 与 sing-box 内核必须分别冻结，且验证器必须读取真实二进制版本而不是只信包数据库；设备版本只作为兼容性观察，不替代 v1.2.1 + v1.12.25 基线 fixture。

协议矩阵中的“目标校验”只对列出的目标版本成立。新补丁版本先运行兼容矩阵，成功后通过适配器数据发布，不隐式扩大旧目标范围。

项目标识固定为 ProxyLoom、Go module `github.com/doujialong/proxyloom`、镜像 `ghcr.io/doujialong/proxyloom`。首次公开源码仓库使用用户授权的 `doujialong/proxyloom`。

## 后果

- M1-M4 不会为“1.12.x”任意未来版本承担未测试兼容承诺。
- Momo Target Profile 同时记录精确 wrapper 与 core 版本；只更新其中一项也必须产生新的 Profile 版本并重跑目标校验。
- sing-box v1.13.14 用于验证扩展性，但不阻塞第一个 P0 纵向切片。
- 上游出现新稳定版时更新本 ADR 或新增 ADR，并保留旧目标配置用于历史构建重放。
