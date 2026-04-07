# 安装

## 环境要求

- Python 3.10 及以上
- 使用 `uv` 管理本地环境，或使用 `pip` 安装发布包
- 可选安装 `semgrep`，用于第一轮规则扫描

## 从 PyPI 安装

```bash
pip install aion-evolve
```

或者：

```bash
uv tool install aion-evolve
```

## 从源码安装

```bash
git clone https://github.com/shenxianpeng/aion.git
cd aion
uv sync --group dev --group docs
```

## 配置 API 访问

`scan` 至少需要一个模型提供方：

```bash
export ANTHROPIC_API_KEY=your_key
```

或者：

```bash
export OPENAI_API_KEY=your_key
```

## 验证 CLI

```bash
uv run aion --help
```

## 可选的文档本地预览

```bash
uv run mkdocs serve
```
