# Codex 原生会话迁移设计

## 目标

用户从另一台电脑导出的 AgentArk `.ahbundle` 恢复后，目标电脑的 Codex
客户端可以列出并继续使用这些会话。AgentArk 自有 SQLCipher 索引继续保存
跨 Agent 浏览、校验和审计副本。

## 关键结论

当前 Codex CLI 0.146.0 的 `thread/inject_items` 只把 Responses API item
放入模型上下文，不会形成 `thread/list` 可见的历史 turns。隔离验证确认，
复制一份 Codex 已经接受的 rollout JSONL 到新的 `CODEX_HOME` 后，重新启动
App Server 可以发现并读取该 thread。因此迁移实现必须复制合法 rollout 载荷，
而不是猜测私有事件格式或重新生成 CanonicalSession 的伪 rollout。

## 数据与安全边界

- 源设备扫描只读；导出从 `CODEX_HOME/sessions` 读取与已索引
  `source_session_id` 匹配的 rollout。
- 每个 JSONL 行解析后使用 `SecretScanner` 脱敏，删除 `reasoning` 和
  `agent_reasoning` 记录；不复制凭据、隐藏推理或不可验证的工具内部数据。
- Codex thread/session ID 保持原值；AgentArk CanonicalSession ID 只作为
  bundle 条目映射键。这样 Codex 能看到原始 thread，AgentArk 仍能关联项目。
- 仅重写 JSON 对象中键名为 `cwd` 或 `workspace_roots` 的路径字符串，指向
  目标 `restored-workspaces/<workspace-id>`；用户消息普通文本中的路径不改。
- bundle 使用 `native/codex/<canonical-session-id>/<relative-rollout>` 条目，
  复用现有 entry hash 和安全相对路径校验。

## 恢复流程

1. 用户关闭 Codex，在 AgentArk 迁移页点击“导出会话历史”，选择 Codex、项目
   和项目文件，保存 `.ahbundle`。
2. 目标设备关闭 Codex，点击“导入会话历史”，选择 `.ahbundle`；AgentArk
   先校验 bundle、项目冲突并展示预览。
3. 用户确认后，先恢复 AgentArk 索引和项目文件，再执行 Codex 原生恢复（仅
   Codex 且勾选该选项时）。
4. 目标 Codex 可执行文件先做精确版本/stdio App Server 探测；Windows 下
   通过 `tasklist` 检查 Codex 客户端未运行。未知版本、进程仍在运行或探测
   失败时不写 Codex，但保留已经完成的 AgentArk 归档并报告原因。
5. 对每个载荷按原相对路径写入目标 `CODEX_HOME/sessions`。目标已存在且
   hash 相同则幂等跳过；hash 不同则阻止覆盖并报告冲突。
6. 启动目标版本 App Server，调用 `thread/resume`、`thread/list`、
   `thread/read(includeTurns=true)`，核对 thread ID、cwd 和 turns。任何验证
   失败都删除本次新增文件；AgentArk 归档不回滚。
7. 报告导入/跳过/冲突数和备份目录，提示用户重新启动 Codex 刷新会话列表。

## 备份与回滚

- 备份目录为 `CODEX_HOME/agentark-backups/<timestamp>`，包含 manifest、hash
  和受影响目标文件副本；不会删除或覆盖源文件。
- rollout 先写唯一同目录临时文件，`sync_all` 后 rename。
- 原生验证失败时只删除本次恢复报告中的 `written_paths`；已存在的同 hash
  文件保留。
- 原生失败以单独报告字段返回，不掩盖 AgentArk 索引恢复成功状态。

## UI/API

- 现有“导出会话历史”和“导入会话历史”按钮保持不变，继续使用系统保存/打开
  对话框，不要求用户手填路径。
- Codex 预览显示默认开启的“恢复到 Codex 客户端”选项及重启提示；非 Codex
  不显示该选项。
- `bundle_restore` 接收 `nativeTarget`；`BundleReport` 返回
  `nativePayloadCount`、`nativeImportedCount`、`nativeSkippedCount`、
  `nativeConflictCount`、`nativeBackupPath`、`nativeRestartRequired` 和
  脱敏后的 `nativeError`。

## 验收标准

- 隔离临时 `CODEX_HOME` 中，原始和脱敏后的合法 rollout 均能在 App Server
  重启后被 `thread/list` 列出，并由 `thread/read` 返回 turns。
- 重复导入同一 bundle 幂等；不同 hash 冲突不会覆盖目标。
- Codex 运行中、未知版本、配置缺失、路径非法和验证失败不破坏原有目标文件。
- AgentArk 原有导出/导入、项目文件凭据排除、多 Agent 分类和前端功能全部
  保持可用。
