# ADR-0006：构建清单与原子发布

- 状态：Accepted
- 日期：2026-07-17
- 对应需求：BUILD-005 至 BUILD-008

## 背景

只记录“健康截止时间”或当前流水线版本不足以重放历史构建。名称分配和健康结果会在相同源快照下改变，旧任务也可能晚于新任务结束。

## 决策

每个 Artifact 保存规范 JSON 构建清单，至少固定：

- schema 版本、Artifact/Output ID、Output Revision ID 和构建原因；
- Collection、Pipeline、Template Revision 与 Template Snapshot ID；
- 有序 Source Snapshot ID、内容摘要和 Raw Document 摘要；
- Target Profile ID/版本、协议注册表、适配器与目标验证器版本；
- Node Occurrence 关联算法版本；
- Name Allocation Snapshot ID、分配项 ID 和分配版本；
- Health Policy/Probe Profile Revision、每个采用的 Health Record ID、状态和探测时间，以及采用的 Probe Batch ID、结论、有效样本计数和精确 Control Probe Record ID；
- 显式动态输入、排序规则版本、渲染器版本、服务版本、平台和构建输入摘要。

清单以 RFC 8785 规范 JSON 编码并计算 SHA-256。Artifact 内容在同一目标平台必须逐字节确定；JSON 输出固定 UTF-8、LF、两空格缩进、键顺序和结尾换行。创建 Artifact、保存清单和校验结果在一个事务内完成。

发布切换使用单行 `output_publications` 比较并交换：只有任务固定的 Output Revision 仍是期望修订，且其构建序号不早于当前自动发布序号时才能切换。手工回滚使用独立的发布模式和审计记录。发布端点永远读取已提交 Artifact，不在请求路径重建。

## 后果

- 历史构建不读取“当前”健康状态或名称映射，能够解释和回滚。
- 清单会较大；Health Record 和 Name Allocation 通过不可变 ID 引用，保留清理必须保护仍被 Artifact 引用的记录。
- 跨平台逐字节一致不是 P0 承诺；平台字段必须固定，CI 分别验证 amd64/arm64 的确定性。
