# 工作原理

AION 只跑一条流水线：**扫描 → 检测 → 修复 → 验证 → 出 PR**。其余功能（漂移检测、
watch 循环）都复用同一套检测与修复内核。

## 1. 构建仓库上下文

在判断某处是否有风险之前，AION 先提取一份轻量的仓库画像：

- import 与主导框架用法
- 鉴权装饰器（只识别真正像鉴权的那些）
- 数据库访问模式
- 函数名
- 可能的 ORM 和 HTTP 客户端约定

有了上下文，AION 就能把 finding 落到*你的*代码写法上，而不只是通用规则命中。

## 2. 检测问题

检测结合：

- 安装了 Semgrep 时运行 `semgrep --config p/python`
- 仓库特定的回退启发式规则
- 对上下文敏感的 finding 使用可选的 LLM 解释

可处理的结果会被升级为 incident，带上严重级别、置信度、证据、修复策略和验证策略。

## 3. 生成确定性补丁产物

对支持的问题类型，AION 生成确定性补丁，而不是就地改写仓库。每个产物都包含原始内容、
补丁内容、统一 diff、所应用的 plan，以及静态校验标记。

支持的确定性修复：

| 问题类型 | 修复方式 |
|---|---|
| `hardcoded_secret` | 把字面量改为 `os.getenv(...)` |
| `raw_sqlite_query` | 把 `cursor.execute` 改为参数化调用 |
| `insecure_yaml_load` | `yaml.load` → `yaml.safe_load` |
| `command_injection` | 用 `shlex.quote` 包裹 `os.system` f-string 变量 |
| `subprocess_shell_injection` | 用 `shlex.quote` 包裹 `subprocess(... shell=True)` 变量 |
| `eval_injection` | `eval(...)` → `ast.literal_eval(...)` |
| `weak_cryptography` | `hashlib.md5` → `hashlib.sha256` |

`missing_auth_decorator` 会被检测，但**只报告**——上报给人工，绝不自动打补丁。

## 4. 验证

每个补丁在变成 Pull Request 之前，都必须先通过一道独立的验证门：

- **语法** —— 补丁内容必须能作为 Python 解析。
- **断言** —— 用 AST 检查确认*具体的*修复确实生效（例如 `cursor.execute` 现在已参数化、
  secret 现在已是 `os.getenv` 查找）。这与生成补丁的正则相互独立。
- **Semgrep 重扫** —— 安装了 Semgrep 时，打补丁后的文件必须重扫干净。

判定结果是 `verified_fix`、`unsafe_patch` 或 `needs_human_review` 之一。
只有 `verified_fix` 才会继续走向 Pull Request。

## 5. 出 PR

`auto-update` 为每个已验证修复开一个 Pull Request，套用 `.aion.yaml` 中的标签、
评审者、指派人和目标分支，并遵守 `open_pull_requests_limit`。任何不是已验证修复的内容
都会留给人工复核，而不会提交。

## 6. 漂移检测与 watch 循环

同一套检测/修复内核驱动持续监控。

### 漂移检测

`aion snapshot` 在某个时间点捕获安全指纹（文件哈希 + 问题 + 健康分）。`aion drift`
把当前状态与该基线对比，识别回归并计算健康分变化。

| 状态 | 默认位置 |
|---|---|
| 快照 | `.aion/snapshots/` |

健康分是 0.0–1.0 的指标：1.0 表示没有已知问题；分数越低，反映相对仓库规模的问题严重度与数量越高。

### 知识库

每次修复都会把结果（按问题类型与策略记录成功/失败）写入
`.aion/knowledge/patterns.json`。`aion status` 会展示这份历史。它是修复表现随时间变化的审计记录。

### watch 模式

`aion watch` 跑外层循环：轮询 → 检测漂移 → 自动修复已验证项 → 记录 → 刷新基线。

## 7. 边界

AION 产出补丁产物和 Pull Request。它不会在线热修生产代码，不接入
WAF/网关/feature-flag/部署系统，也不处理运行时事件流。当前版本只支持 Python。
