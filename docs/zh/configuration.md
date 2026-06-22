# 配置

在目标仓库根目录放置 `.aion.yaml`。AION 用它控制扫描默认值和 `auto-update` 的
Pull Request 工作流。配置采用扁平格式。

## 示例

```yaml
provider: openai
model: gpt-4.1
ignore_paths:
  - tests/*
  - scripts/generated_*.py
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

命令行参数会覆盖 `.aion.yaml` 中对应的配置。

## 字段

### 扫描

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `provider` | string | `null` | 扫描时的 LLM 提供方：`anthropic`、`openai`、`gemini`、`azure`、`deepseek` 或 `qwen` |
| `model` | string | 提供方默认 | `scan` 的显式模型覆盖 |
| `ignore_paths` | list | `[]` | 扫描时跳过的 glob 模式 |

### Auto-update（Pull Request）

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `directory` | string | `/` | 要处理的相对目录 |
| `open_pull_requests_limit` | integer | `5` | AION 同时打开的最大 PR 数 |
| `labels` | list | `[]` | 自动创建的 PR 上加的标签 |
| `reviewers` | list | `[]` | 自动创建的 PR 上请求的评审者 |
| `assignees` | list | `[]` | 自动创建的 PR 的指派人 |
| `target_branch` | string | `main` | 自动创建的 PR 的基础分支 |
| `commit_message_prefix` | string | `[AION]` | 提交信息和 PR 标题的前缀 |

## 支持的 LLM 提供方

| 提供方 | 环境变量 | 默认模型 |
|---|---|---|
| Anthropic | `ANTHROPIC_API_KEY` | `claude-3-5-sonnet-latest` |
| OpenAI | `OPENAI_API_KEY` | `gpt-4.1` |
| DeepSeek | `DEEPSEEK_API_KEY` | `deepseek-chat` |
| Qwen（通义） | `QWEN_API_KEY` | `qwen-plus` |
| Gemini | `GEMINI_API_KEY` | `gemini-2.0-flash` |
| Azure OpenAI | `AZURE_OPENAI_API_KEY` | `gpt-4` |

## 解析规则

- 命令行参数覆盖 `.aion.yaml` 中对应的配置。
- `scan` 和 `auto-update` 从目标仓库根目录读取配置。

## 运维说明

- `provider` 和 `model` 只影响 `scan`；确定性的 `repair`、`verify`、`auto-update`
  都不需要 LLM。
- 上下文提取结果缓存在 `~/.aion-context.json`。
- 出于文档目的，配置仍接受 `schedule:` 块（AION 本身按需运行，或按你工作流里的 cron 运行），
  早期版本遗留的未识别字段同样会被解析但不产生任何效果。
