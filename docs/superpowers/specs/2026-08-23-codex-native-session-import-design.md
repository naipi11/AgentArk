# Codex 原生会话迁移设计

## 目标

让用户从另一台电脑导出的 AgentArk `.ahbundle` 中恢复 Codex 会话后，
在目标电脑的 Codex 客户端会话列表中看到这些会话，并能继续使用 Codex
原生 thread 继续对话。AgentArk 自己的加密索引仍保留为校验、审计和跨
Agent 浏览副本。

## 当前边界与探测结论

当前 AgentArk 的 `bundle_restore` 只写 AgentArk 自有 SQLCipher 索引和
`restored-workspaces`，不会写入 `CODEX_HOME`，因此不能满足 Codex 客户端
可见性要求。

目标机当前 Codex CLI 为 0.146.0。其 App Server 暴露了 `thread/start`、
`thread/resume`、`thread/name/set` 和实验性的 `thread/inject_items`。
隔离探针确认 `thread/inject_items` 会在 rollout 中写入 Responses API
item，但 `thread/read` 的 turns 和 `thread/list` 仍为空；因此不能仅依赖
该接口实现侧边栏可见的完整历史。

相同版本的第二个隔离探针把一份已知合法的 rollout 复制到临时
`CODEX_HOME`，重启 App Server 后 `thread/list` 能发现该 thread。由此确认
当前版本的可靠边界是“生成符合 Codex rollout 事件结构的文件，再让 Codex
重新索引”，而不是只注入模型上下文。

Codex 官方协议支持按 rollout path 恢复 thread，且 thread 的可见历史由
`session_meta`、`task_started`、`turn_context`、`response_item`、用户/助手
事件和 `task_complete` 等 JSONL 记录共同构成。由于该存储属于供应商格式，
必须按版本探测、生成后验证、原子发布和可回滚处理，不能把未知版本当作兼容。

## 用户可见流程

1. 用户在源设备关闭 Codex，在 AgentArk 的迁移页选择 Codex、项目和会话，
   点击“导出会话历史”。导出包继续使用现有 `.ahbundle` 格式。
2. 用户在目标设备关闭 Codex，安装 AgentArk，点击“导入会话历史”并选择
   `.ahbundle`。
3. AgentArk 先执行现有 bundle 校验、项目文件冲突检查和 AgentArk 索引
   预览。
4. 用户确认恢复后，AgentArk 先恢复自身索引和项目文件，再对 Codex 执行
   原生恢复：为每个会话生成新的 Codex thread ID，写入可验证的 rollout，
   通过 App Server `thread/resume` 验证，然后原子发布到目标 `CODEX_HOME`。
5. AgentArk 显示原始会话 ID、新 Codex thread ID、可见会话数、跳过数和失败
   原因。用户重新启动 Codex 后，在 Codex 客户端会话列表中查看和继续会话。

## 原生 thread 物化

### ID 与元数据

- 原始 CanonicalSession ID 只作为 AgentArk 映射键，不强行伪造 Codex ID。
- 每个导入会话生成新的 UUIDv7 Codex thread/session ID，并写入
  `session_meta.session_id`、`session_meta.id` 与 rollout 文件名。
- `cwd` 使用已恢复项目目录；没有项目文件时使用会话原始工作目录的安全
  目标映射或显式的新工作区目录。
- 会话标题通过 App Server `thread/name/set` 设置；AgentArk 保存
  `source_session_id -> target_thread_id` 映射和源/目标 hash。

### 可见消息映射

- Canonical user message 映射为 Codex `response_item` 的 user message，并配套
  `event_msg.user_message`。
- Canonical assistant message 映射为 Codex `response_item` 的 assistant
  message，并配套 `event_msg.agent_message`。
- 每个连续会话段生成 `task_started`、`turn_context` 和 `task_complete`，使
  Codex 能重建 turns 和预览。
- Tool event 只迁移清洗后的可见摘要；不伪造隐藏 reasoning、凭据、内部
  call token 或不可验证的工具执行结果。
- 附件、图片和模型隐藏推理不能在当前 Canonical contract 下保证原样恢复，
  必须在报告中标为 partial/loss，而不是静默丢失。

## 兼容性、备份与回滚

- Codex writer 只在 probe 确认可支持的 CLI 版本和 rollout schema fingerprint
  时启用；未知版本默认为“仅恢复 AgentArk，不写 Codex”。
- 写入前生成目标 `CODEX_HOME` 受保护备份，至少覆盖 `sessions`、相关索引/状态
  文件和本次写入清单；备份路径只进入审计元数据，不进入会话正文。
- 所有 rollout 先写同目录唯一临时文件，`flush`/`sync_all` 后重命名；同一
  thread ID 已存在且 hash 相同则幂等跳过，hash 不同则阻止覆盖并报告冲突。
- 临时 rollout 发布后，启动隔离 App Server 调用 `thread/resume`、`thread/read`
  和 `thread/list` 验证 thread、标题、cwd、turn 数和可见文本；验证失败时删
  除本次临时文件并恢复备份状态。
- Codex 正在运行时不执行原生写入，UI 必须明确提示用户先关闭 Codex；AgentArk
  不强制杀死用户进程。恢复完成后提示重新启动 Codex 刷新侧边栏。
- AgentArk 自有索引恢复失败和 Codex 原生恢复失败分别记录审计事件；原生
  失败不回滚已经验证通过的 AgentArk 归档，但报告必须明确两者状态不同。

## UI 与 API

- 现有“导出会话历史”和“导入会话历史”按钮保持不变。
- Codex 导入预览增加“恢复到 Codex 客户端”状态、备份位置、目标 thread 数、
  partial/loss 数和“需要重启 Codex”提示；非 Codex Agent 继续使用 AgentArk
  索引恢复流程。
- `BundleReport` 增加 `nativeTarget`、`nativeImportedCount`、
  `nativeSkippedCount`、`nativeConflictCount`、`nativeBackupPath` 和
  `nativeRestartRequired` 等 sanitized 字段。
- 新增 Tauri command/service `bundle_restore_codex_native`，输入已验证 bundle
  路径和目标 Agent 安装信息，输出上述报告；它不得接受任意 SQL 或任意 vendor
  文件写入路径。

## 验收标准

- 在临时 Codex home 上，导入至少一个 user/assistant 多轮会话后，App Server
  `thread/read` 返回 turns，`thread/list` 返回新 thread，Codex 客户端重启后
  能打开并继续该 thread。
- 重复导入相同 bundle 幂等；目标同名 thread hash 不同则阻止覆盖。
- Codex 运行中、未知版本、rollout 校验失败、文件冲突和中断写入均不破坏
  原有 `CODEX_HOME`，并产生可审计、无正文泄露的失败报告。
- 原有 AgentArk 导出/导入、非 Codex Agent、项目文件排除凭据和只读扫描测试
  全部继续通过。
