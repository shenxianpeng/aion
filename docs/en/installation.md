# Installation

## Requirements

- Python 3.11 or newer
- `uv` for environment management
- Optional: `semgrep` for the rule-based first pass

## Local setup

```bash
git clone https://github.com/shenxianpeng/aion.git
cd aion
uv sync --dev
```

## API keys

Choose at least one provider:

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
