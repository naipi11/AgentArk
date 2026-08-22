# Agent 分类与跨设备会话历史迁移设计

## 目标

让用户能够按 Agent 浏览项目/会话，并通过“导出会话历史”和“导入会话历史”完成带项目文件的跨设备恢复，同时保持源 Agent 数据只读、凭据不迁移、导入可校验可回滚。

## 范围

- Projects、Sessions、Timeline、Search 共享同一个可选 Agent filter。
- 导出当前选择的 Agent 与项目范围，生成 Agent 专属 `.ahbundle`。
- bundle 包含规范化会话、原始捕获证据、项目清单、选择的项目文件和 SHA-256 元数据。
- 导入先执行校验和预览，再以合并或新项目模式恢复到 AgentArk 索引。
- 对没有公开原生导入契约的供应商只生成 L1 handoff，不直接改供应商私有数据库。

## Agent filter 数据契约

`agent_installs.kind` 是唯一分类来源；UI 值固定为 `all | codex | claude-code | hermes | openclaw | opencode | grok-build`。查询接口接受 `agent_kind: Option<AgentKind>`，`None` 表示全部。项目统计和会话列表必须在同一个事务快照中使用相同 filter，避免数量与列表不一致。

## Agent-specific bundle

manifest 新增：

```json
{
  "format": "1.1",
  "agent": "codex",
  "sourceRoot": "file:///...",
  "sessionCount": 3,
  "workspaceCount": 2,
  "fileCount": 18,
  "redacted": true,
  "entries": []
}
```

目录约定：

```text
manifest.json
sessions/<session-id>.ndjson
workspaces/<workspace-id>/manifest.json
workspaces/<workspace-id>/files/<relative-path>
objects/<sha256>
reports/verification.json
```

导出时仅允许用户明确选择的工作区根目录内普通文件；拒绝符号链接、junction、绝对路径、`..`、设备路径和超出大小上限的文件。凭据文件（auth、token、cookie、密钥）不进入 bundle。文本内容经过 SecretScanner，二进制只保留 hash 和用户明确选择的字节。

## Import flow

1. `bundle_inspect` 读取 magic、manifest、entry hash，并返回 Agent/项目/会话/文件统计。
2. UI 展示校验结果和冲突列表；默认模式为“恢复为新项目”，避免覆盖现有数据。
3. 用户选择合并或新项目后，导入器创建 checkpoint，在单一 SQLCipher 事务中写入 AgentArk 自有索引/CAS。
4. 导入后重新计算会话、项目文件 hash；任意不一致都 rollback checkpoint。
5. 导入不自动写 vendor 私有状态；可输出 L1 handoff，目标 Agent 原生 API 后续单独启用。

## UI

- Projects/Sessions 顶部增加 Agent selector，默认 All Agents。
- Status 页的迁移区域改成两个主按钮：`导出会话历史`、`导入会话历史`。
- 导出对话框包含 Agent selector、项目多选、文件范围和输出路径。
- 导入对话框包含 bundle 路径、预览、冲突列表、恢复模式和确认按钮。

## 错误与安全

- 未知 bundle schema、缺失 entry、hash mismatch、path traversal、权限不足均 fail-closed。
- 导入过程中断后，checkpoint 保留且索引不发布半成品。
- 所有导出/导入操作写入 hash-chain audit event；日志只写路径 basename、数量和 hash，不写正文或凭据。

## 验收标准

- 每个 Agent filter 的项目数量与会话列表准确，All Agents 行为保持兼容。
- 每个 Agent 至少一个 fixture 能导出、inspect、导入并恢复会话与项目 manifest。
- 选择的项目文件 SHA-256 在导入后完全一致；重复导入幂等。
- 恶意路径、超大 entry、secret canary 和损坏 bundle 均被拒绝或脱敏。
- Windows MSI/NSIS 构建、升级和桌面启动回归通过。
