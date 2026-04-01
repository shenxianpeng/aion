# 配置

在目标仓库根目录创建 `.aion.yaml`。

## 示例

```yaml
provider: openai
model: gpt-4.1
ignore_paths:
  - tests/*
  - scripts/generated_*.py
```

## 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `provider` | string | `anthropic` 或 `openai` |
| `model` | string | 显式指定模型名 |
| `ignore_paths` | list | 扫描时忽略的 glob 模式 |

## 覆盖优先级

命令行参数优先级高于 `.aion.yaml`。

## 缓存位置

上下文提取缓存保存在：

```text
~/.aion-context.json
```
