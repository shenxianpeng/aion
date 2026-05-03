# 配置

在目标仓库根目录放置 `.aion.yaml`。AION 用它控制仓库扫描默认值、编排命令，以及自动更新工作流。

AION 使用扁平配置格式。`schedule`、`open_pull_requests_limit` 和
`labels` 等自动更新字段直接配置在顶层。

## 扁平配置格式

```yaml
directory: "/"
schedule:
  interval: "weekly"
  day: "monday"
  time: "09:00"
  timezone: "Asia/Shanghai"
provider: openai
model: gpt-4.1
ignore_paths:
  - tests/*
  - scripts/generated_*.py
auto_repair_issue_types:
  - raw_sqlite_query
  - hardcoded_secret
  - missing_auth_decorator
auto_repair_min_confidence: 0.90
sandbox_mode: repository
sandbox_verification_commands:
  - python -m pytest tests/unit
auto_approve_verified_fixes: false
rollback_on_verification_failure: true
open_pull_requests_limit: 5
labels:
  - "aion"
  - "security"
reviewers:
  - "team:security"
assignees:
  - "username"
target_branch: "main"
commit_message_prefix: "[AION]"
```

## 字段说明

### 核心字段

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `provider` | string | `null` | `scan` 阶段使用的 LLM 提供方，支持 `anthropic`、`openai`、`deepseek` 或 `qwen` |
| `model` | string | provider 默认值 | `scan` 的显式模型覆盖 |
| `ignore_paths` | list | `[]` | 仓库扫描时跳过的 glob 模式 |
| `auto_repair_issue_types` | list | 内建集合 | 允许进入自动 sandbox 修复的 incident 类型 |
| `auto_repair_min_confidence` | float | `0.85` | 触发自动修复所需的最小 incident 置信度 |
| `sandbox_mode` | string | `repository` | `file` 为单文件 staging，`repository` 为整仓 staging |
| `sandbox_verification_commands` | list | `[]` | 在 staged sandbox 内执行的项目级命令 |
| `auto_approve_verified_fixes` | boolean | `false` | staged 验证通过时直接给出 `approved_for_rollout` |
| `rollback_on_verification_failure` | boolean | `true` | staged 验证失败时给出 `rollback`，而不是 `needs_human_review` |

### 自动更新字段

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `directory` | string | `/` | 操作的相对目录 |
| `schedule.interval` | string | `weekly` | `daily`、`weekly` 或 `monthly`（供参考；AION 本身按需运行） |
| `schedule.day` | string | `monday` | `weekly` 间隔对应的星期 |
| `schedule.time` | string | `09:00` | 时间（24 小时制） |
| `schedule.timezone` | string | `UTC` | 调度时区 |
| `open_pull_requests_limit` | integer | `5` | 最大并发打开的 AION PR 数 |
| `labels` | list | `[]` | 自动创建的 PR 上打的标签 |
| `reviewers` | list | `[]` | 自动创建的 PR 上请求的评审人 |
| `assignees` | list | `[]` | 自动创建的 PR 的负责人 |
| `target_branch` | string | `main` | 自动创建的 PR 的目标分支 |
| `commit_message_prefix` | string | `[AION]` | 提交信息前缀 |

## 解析规则

- 命令行参数会覆盖 `.aion.yaml` 中对应的配置。
- `scan` 从目标仓库根目录读取配置。
- `process-event`、`process-event-queue` 和 inbox 处理会从事件的 `repo_root` 读取配置。

## 推荐配置档位

保守式 staging：

```yaml
auto_repair_min_confidence: 0.95
auto_approve_verified_fixes: false
rollback_on_verification_failure: false
```

本地快速实验：

```yaml
sandbox_mode: file
auto_approve_verified_fixes: true
rollback_on_verification_failure: true
```

## 运行说明

- `provider` 和 `model` 只影响 `scan`；确定性修复和编排流程本身不依赖 LLM。
- `sandbox_verification_commands` 会在 staged workspace 中执行，并把每条命令结果写入 orchestration record。
- 上下文提取缓存位于 `~/.aion-context.json`。
