# 使用

AION 共有八个命令：`scan`、`repair`、`verify`、`auto-update`、`snapshot`、
`drift`、`watch`、`status`。

## 前置条件

- 运行 `scan` 前至少设置一个 LLM 提供方密钥（`OPENAI_API_KEY`、`ANTHROPIC_API_KEY`、
  `GEMINI_API_KEY`、`DEEPSEEK_API_KEY` 或 `QWEN_API_KEY`）。确定性的
  `repair` / `verify` / `auto-update` **不需要** LLM。
- 如需 auto-update 默认配置，把 `.aion.yaml` 放在目标仓库根目录。
- 需要机器可读输出时使用 `--output json`。

## 1. 扫描仓库

```bash
uv run aion scan ./path/to/project
```

只扫描你已知是 AI 生成的文件：

```bash
uv run aion scan ./path/to/project \
  --ai-generated ./path/to/project/generated_file.py
```

切换提供方或输出 JSON：

```bash
uv run aion scan ./path/to/project --provider openai --output json
```

打印提取出的上下文、回退原因和 Semgrep 细节：

```bash
uv run aion scan ./path/to/project --verbose
```

## 2. 生成并验证修复产物

生成确定性补丁产物（不需要 LLM）：

```bash
uv run aion repair ./path/to/file.py \
  --context-file ./context.json \
  --artifact-path ./artifact.json \
  --record-path ./repair-record.json
```

验证已有产物——语法检查、断言修复确实生效的 AST 检查、以及（安装了 Semgrep 时的）
Semgrep 重扫：

```bash
uv run aion verify --artifact-path ./artifact.json
```

只有判定为 `verified_fix` 才算修复成功。

## 3. Auto-update：扫描 → 验证 → 开 PR

运行完整流程：

```bash
uv run aion auto-update --target ./
```

干跑（dry-run），查看会发生什么但不创建 PR：

```bash
uv run aion auto-update --target ./ --dry-run
```

`auto-update` 命令会：

1. 读取 `.aion.yaml` 中的提供方与 PR 配置。
2. 扫描所有 Python 文件中的安全问题。
3. 为支持的问题类型生成确定性补丁。
4. 在隔离工作区中验证每个补丁。
5. 为每个**已验证**的修复开 Pull Request。
6. 遵守 `open_pull_requests_limit`，避免 PR 泛滥。

### GitHub Action

AION 自带可复用的 GitHub Action（`action.yml`）。加入工作流：

```yaml
name: AION Auto-Update
on:
  schedule:
    - cron: '0 9 * * 1'  # 每周一 09:00 UTC
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write

jobs:
  auto-update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - uses: shenxianpeng/aion@main
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
```

## 4. 支持的问题类型

`scan` 能报出很多 finding，但只有下面这些会被转成确定性、可验证的自动修复：

| 问题类型 | 修复方式 |
|---|---|
| `hardcoded_secret` | 把字面量改为 `os.getenv(...)` |
| `raw_sqlite_query` | 把 `cursor.execute` 改为参数化调用 |
| `insecure_yaml_load` | `yaml.load` → `yaml.safe_load` |
| `command_injection` | 用 `shlex.quote` 包裹 `os.system` f-string 变量 |
| `subprocess_shell_injection` | 用 `shlex.quote` 包裹 `subprocess(... shell=True)` 变量 |
| `eval_injection` | `eval(...)` → `ast.literal_eval(...)` |
| `weak_cryptography` | `hashlib.md5` → `hashlib.sha256` |

`missing_auth_decorator` 是**只报告**：缺失鉴权会上报给人工，但绝不自动注入——
因为 AION 无法判断哪个装饰器才正确，也无法判断该路由是否本就有意公开。

## 5. 跟踪安全漂移

### 保存安全基线

```bash
uv run aion snapshot ./src --name baseline
```

这会生成 `.aion/snapshots/baseline.json`，包含健康分、问题列表和文件哈希——
仓库安全状态的可复现指纹。

### 检测漂移

```bash
uv run aion drift ./src --name baseline
```

退出码 `0` 表示无回归；退出码 `1` 表示发现新问题。在 CI 中可用 `--output json`
获取机器可读的漂移报告。

### 持续 watch 模式

```bash
uv run aion watch ./src --interval 30 --auto-repair
```

AION 每隔 `--interval` 秒轮询一次，与上一个已知良好基线对比，为新问题生成并验证补丁。
当修复达到 `verified_fix` 时，`watch` 会把补丁写回被监视的本地文件并刷新基线。

### 查看引擎健康

```bash
uv run aion status
# 或指定自定义 .aion 目录
uv run aion status --aion-dir ./.aion --output json
```

`status` 展示累积的快照和修复知识库（修复过程中记录的每种问题类型的成功/失败历史）。

## 6. 运维说明

- AION 产出补丁产物和 Pull Request；`watch` 在验证后可改写被监视的本地文件，
  但不会就地改写线上生产文件。
- 确定性的 `repair`、`verify`、`auto-update` 不需要 LLM；只有 `scan` 的解释需要。
- 漂移快照和知识库历史持久化在 `.aion/` 下，重启后仍保留。
- 上下文提取结果缓存在 `~/.aion-context.json`。
