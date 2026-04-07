# Installation

## Requirements

- Python 3.10 or newer
- `uv` for local environment management, or `pip` for package installation
- Optional: `semgrep` for the fast rules-based first pass

## Install from PyPI

```bash
pip install aion-evolve
```

or

```bash
uv tool install aion-evolve
```

## Install from source

```bash
git clone https://github.com/shenxianpeng/aion.git
cd aion
uv sync --group dev --group docs
```

## Configure API access

`scan` requires at least one provider API key:

```bash
export ANTHROPIC_API_KEY=your_key
```

or

```bash
export OPENAI_API_KEY=your_key
```

## Verify the CLI

```bash
uv run aion --help
```

## Optional documentation preview

```bash
uv run mkdocs serve
```
