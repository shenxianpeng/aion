# 安装

## 环境要求

- Python 3.11 及以上
- 使用 `uv` 管理环境
- 可选安装 `semgrep`，用于第一轮规则扫描

## 本地安装

```bash
git clone https://github.com/shenxianpeng/aion.git
cd aion
uv sync --dev
```

## 配置 API Key

至少配置一个模型提供方：

```bash
export ANTHROPIC_API_KEY=your_key
```

或者：

```bash
export OPENAI_API_KEY=your_key
```

## 验证命令

```bash
uv run aion --help
```
