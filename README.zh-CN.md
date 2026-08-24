<div align="center">
  <img src="AgentArk.png" alt="AgentArk 图标" width="144" height="144">
  <h1>AgentArk</h1>
  <p><strong>面向编程 Agent 会话历史的本地优先归档、搜索、备份与安全恢复工具。</strong></p>
  <p>中文 · <a href="./README.md">English</a></p>
</div>

<p align="center">
  <a href="https://github.com/naipi11/AgentArk/releases/latest"><img src="https://img.shields.io/github/v/release/naipi11/AgentArk?display_name=tag&sort=semver&style=flat-square&label=release&color=2563eb" alt="最新版本"></a>
  <a href="https://github.com/naipi11/AgentArk/releases"><img src="https://img.shields.io/github/downloads/naipi11/AgentArk/total?style=flat-square&label=downloads&color=7c3aed" alt="总下载量"></a>
  <a href="https://github.com/naipi11/AgentArk/stargazers"><img src="https://img.shields.io/github/stars/naipi11/AgentArk?style=flat-square&label=stars&color=f59e0b" alt="GitHub 星标"></a>
  <a href="https://github.com/naipi11/AgentArk/pulls"><img src="https://img.shields.io/github/issues-pr/naipi11/AgentArk?style=flat-square&label=pull%20requests&color=0ea5e9" alt="拉取请求"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Windows-10%2F11%20x64-0078D4?style=flat-square&logo=windows&logoColor=white" alt="Windows 10 和 11 x64">
  <img src="https://img.shields.io/badge/macOS-Apple%20silicon-000000?style=flat-square&logo=apple&logoColor=white" alt="macOS Apple 芯片">
  <img src="https://img.shields.io/badge/Linux-x64-FCC624?style=flat-square&logo=linux&logoColor=111827" alt="Linux x64">
  <img src="https://img.shields.io/badge/Tauri-2-24C8DB?style=flat-square&logo=tauri&logoColor=white" alt="Tauri 2">
  <img src="https://img.shields.io/badge/Rust-2024-000000?style=flat-square&logo=rust&logoColor=white" alt="Rust 2024">
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=111827" alt="React 19">
  <img src="https://img.shields.io/badge/Storage-Encrypted%20local-16a34a?style=flat-square&logo=sqlite&logoColor=white" alt="本地加密存储">
</p>

AgentArk 将本机编程 Agent 的会话和项目工作区统一整理为可搜索的加密档案。你可以选择项目导出、迁移会话到另一台设备、查看恢复结果，并保留可审计记录；全过程不上传你的会话内容。

## 为什么选择 AgentArk

- 本地优先的加密归档与全文搜索
- 按项目浏览会话，提供时间线、隔离区与恢复报告
- 可携带的 `.ahbundle` 导出/导入，并可选择包含哪些项目文件
- 审计链、冲突检测、回滚与安全诊断报告
- 桌面客户端支持中文和英文
- 原生 Windows、macOS 与 Linux 桌面安装程序；日常使用无需命令行

## v0.6.1 包含的功能

- 面向 Codex、Claude Code、Hermes、OpenClaw、OpenCode 和 Grok Build 的按 Agent 项目与会话浏览
- 中文 / 英文桌面界面，以及可携带的 `.ahbundle` 导出/导入流程
- 当无法保留原始原生身份时，为 Codex 创建经过验证、与提供方无关的续接会话
- 面向 Windows、Apple 芯片 macOS 和 Linux 的已发布桌面安装包
- 耗时扫描会在桌面窗口线程之外执行，建立索引期间 AgentArk 仍可保持响应

## 恢复能力

| Agent | 当前恢复行为 |
| --- | --- |
| Codex | 当提供方兼容时保留经验证的原生会话 ID；无法保留时，使用目标设备已配置的提供方/模型创建独立验证的续接会话 |
| Claude Code | 完整归档恢复；原生续接写入器等待其协议验证门槛完成 |
| Hermes | 完整归档恢复；原生续接写入器等待验证 |
| OpenClaw | 完整归档恢复；原生续接写入器等待验证 |
| OpenCode | 完整归档恢复；原生续接写入器等待验证 |
| Grok Build | 完整归档恢复；原生续接写入器等待验证 |

AgentArk 不会导出提供方凭据、接口密钥、账号标识或隐藏推理内容。只有通过兼容性、进程、模式、可见历史和持久 rollout 验证后，才会尝试原生恢复。无法验证的操作会如实保留为完整归档，而不会伪装成可用的原生会话。

## 安装

1. 打开 [Releases](https://github.com/naipi11/AgentArk/releases/latest)。
2. 按平台选择安装包：
   - **Windows：** `AgentArk_0.6.1_x64-setup.exe`（推荐）或 `AgentArk_0.6.1_x64_en-US.msi`
   - **Apple 芯片 macOS：** `AgentArk_0.6.1_aarch64.dmg`
   - **Linux x64：** `AgentArk_0.6.1_amd64.AppImage`、`.deb` 或 `.rpm`
3. 如需可复现的安装记录，请核对发布的 SHA-256 校验值。
4. 运行安装程序，并从开始菜单或系统应用启动器打开 **AgentArk**。
5. 打开 **扫描**，选择一个 Agent，扫描后即可浏览它的项目和会话。

通常的按用户安装不需要管理员权限。

## 迁移会话到另一台设备

1. 在 **项目** 中选择要迁移的 Agent 和项目。
2. 点击 **导出会话历史**，并在资源管理器中选择保存位置。
3. 将生成的 `.ahbundle` 文件复制到新设备。
4. 在新设备安装 AgentArk 后，点击 **导入会话历史**。
5. 检查检测到的归档，然后选择 **恢复导入的历史**。

AgentArk 会先恢复可搜索的本地归档。对于 Codex，随后会自动保留兼容的原生会话 ID，或创建经验证的续接会话；无需手动选择内部恢复模式。

> [!IMPORTANT]
> 进行原生恢复写入前请关闭 Codex。AgentArk 不会自动结束 Codex 进程。原生恢复完成后，请重启 Codex，让客户端刷新已恢复的会话列表。

## 数据与安全

- 会话归档和索引数据均在本地加密。
- 导出包会在创建前进行脱敏处理。
- 在安全的情况下会保留提供方标签；令牌、接口地址、账号 ID 与隐藏推理内容均会排除。
- 每次恢复都会记录一条哈希链审计事件。
- 即使厂商原生恢复失败，已恢复到 AgentArk 的归档也不会被删除。

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=naipi11/AgentArk&type=Date)](https://star-history.com/#naipi11/AgentArk&Date)

## 开发

使用 `pnpm --dir apps/desktop tauri build` 构建桌面发布版。MSI 和 NSIS 安装程序会生成在 `target/release/bundle/` 下。

有关实现决策、能力契约与后续路线图，请查看 [AgentArk.md](AgentArk.md)。
