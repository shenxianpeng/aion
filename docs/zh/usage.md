# 使用

## 扫描整个仓库

```bash
uv run aion scan ./path/to/project
```

## 只扫描已知的 AI 生成文件

```bash
uv run aion scan ./path/to/project \
  --ai-generated ./path/to/project/generated_file.py
```

## 切换到 OpenAI

```bash
uv run aion scan ./path/to/project --provider openai
```

## 输出 JSON

```bash
uv run aion scan ./path/to/project --output json
```

## 输出详细调试信息

```bash
uv run aion scan ./path/to/project --verbose
```

`--verbose` 会把上下文提取结果、Semgrep 结果、fallback 原因和 token 估算输出到 stderr。

## 推荐使用流程

1. 指向一个仓库或一个已生成文件。
2. 让工具自动识别候选 Python 文件。
3. 查看 AI 文件识别和 `semgrep` 可用性的 warning。
4. 重点阅读 context-aware 的问题解释和修复建议。
