# Codex 原生会话迁移实施计划

## 目标

把 Codex 的已存在会话作为 Codex 自己认可的 rollout JSONL 载荷随
`.ahbundle` 一起导出；在目标设备关闭 Codex 后写入目标 `CODEX_HOME`，让
Codex App Server 重新发现这些 thread。AgentArk 的加密索引仍作为跨 Agent
归档、校验和审计副本。

## 已验证的边界

- Codex CLI 0.146.0 的 `thread/inject_items` 能写入模型上下文，但不会形成
  可在 `thread/list` 中看到的历史 turns，不能作为迁移实现。
- 将一份当前版本已经接受的 rollout 文件复制到隔离 `CODEX_HOME` 后，重启
  App Server 可以通过 `thread/list`、`thread/resume` 和 `thread/read` 看到它。
- 因此不猜测私有事件格式，也不从 CanonicalSession 伪造 rollout；只迁移源
  Codex 已生成的合法 JSONL，并在目标版本上重新验证。

## 实施步骤

### 1. 原生 payload 与 bundle

- `collect_native_rollouts` 在源 `CODEX_HOME/sessions` 中按
  `source_session_id` 找到对应 rollout。
- 每行解析为 JSON，使用既有 `SecretScanner` 脱敏，移除
  `reasoning`/`agent_reasoning` 记录，保留 Codex 事件结构和原始 thread ID。
- `.ahbundle` 新增 `native/codex/<canonical-session-id>/<relative-rollout>`
  条目；旧 bundle 格式仍可读取。
- 目标恢复只接受安全相对路径；仅重写 `cwd` 和 `workspace_roots` 到恢复的
  工作区，不改用户消息中的普通文本路径。

### 2. 原子写入、保护和验证

- Windows 下通过 `tasklist` 拒绝 Codex 运行时写入，不自动结束用户进程。
- 写入前在 `CODEX_HOME/agentark-backups/<timestamp>` 创建 manifest 和受影响
  文件副本；相同 hash 幂等跳过，不同内容拒绝覆盖。
- 目标 Codex 版本和 App Server 能力先探测；未知版本只完成 AgentArk 归档，
  不写入 Codex。
- 每个 rollout 使用同目录临时文件、`sync_all` 和原子 rename。
- 写入后启动隔离 App Server，执行 `thread/resume`、`thread/list`、
  `thread/read(includeTurns=true)`；验证失败删除本次写入文件并报告原生恢复
  失败，AgentArk 归档保持可用。

### 3. 桌面迁移流程

- 保留现有“导出会话历史”和“导入会话历史”按钮；按钮分别弹出保存/打开
  资源管理器对话框。
- Codex bundle 的恢复预览默认勾选“恢复到 Codex 客户端”；非 Codex Agent
  继续只恢复 AgentArk 索引和项目文件。
- 报告导入、跳过、冲突、备份位置、是否需要重启及原生错误；成功后提示
  关闭并重新启动 Codex 刷新会话列表。

### 4. 验证与交付

- 单元测试覆盖 JSONL 脱敏、路径重写、bundle 载荷、冲突和原子恢复。
- 忽略的真实 Codex 集成测试只使用临时 `CODEX_HOME`，不触碰用户目录；已
  用当前 0.146.0 可执行文件验证原始和脱敏 payload 都可被重新发现。
- 发布前运行 Rust/前端测试、clippy、构建和 Tauri 打包；安装验证不执行真实
  用户会话导入。
