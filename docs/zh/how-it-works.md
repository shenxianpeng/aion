# 工作原理

AION 是一个分阶段控制面。它让同一个仓库从静态分析继续走到修复、验证、事件编排、
发布控制和运行时防护，而不需要切换核心数据模型。

## 1. 统一输入信号

AION 可以从以下入口开始：

- 对仓库或文件执行 `scan`
- 单个事件 JSON
- 事件队列 JSON
- 文件型 inbox item
- webhook `POST /events`

这些输入最终都会被统一成结构化 orchestration event。

## 2. 构建仓库上下文

在判断风险前，AION 会先提取一个轻量级仓库画像，包括：

- imports 和主导框架使用习惯
- 鉴权装饰器
- 数据库访问模式
- 函数名
- 可能采用的 ORM 与 HTTP client 约定

这样它就不只是识别通用规则命中，还能识别“偏离当前仓库惯例”的风险。

## 3. 把发现结果提升为 incident

检测链路会结合：

- `semgrep --config p/python`
- 仓库特定 fallback heuristic
- 对上下文敏感问题的可选 LLM 解释

可执行的问题会被提升为 incident，包含严重级别、置信度、证据、修复策略和验证策略。

## 4. 从 incident 生成 patch artifact

对于支持的问题类型，AION 会生成确定性 patch artifact，而不是直接改动 live 仓库：

- 插值式 `sqlite3` 查询改为参数化调用
- 硬编码 secret 改为环境变量读取
- 缺失鉴权装饰器改为注入仓库已有模式

artifact 会记录原始内容、修复后内容、diff、plan 和校验状态。

## 5. 在 sandbox 中验证

artifact 会以两种模式之一 staged 到临时工作区：

- `file`：只复制目标文件
- `repository`：复制整个仓库，并在其中替换目标路径

验证链路会组合：

- Python 语法检查
- Semgrep 重扫
- 内建修复断言
- `sandbox_verification_commands` 中配置的项目级命令

最终会生成 rollout recommendation：

- `approved_for_rollout`
- `rollback`
- `needs_human_review`

## 6. 持久化控制面状态

当前实现把状态保存为本地 JSON artifact。

| 状态 | 默认位置 |
|---|---|
| Inbox 事件 | `.aion/inbox/events/` |
| Inbox 结果 | `.aion/inbox/results/` |
| Release candidate | `.aion/releases/` |
| Repair record | 用户指定的 `--record-path` 或评估目录 |

这让整个流程更容易审计，也更容易被脚本化系统接管。

## 7. 管理 staged rollout

成功的 sandbox 结果可以继续提升为 release candidate。当前发布状态机支持：

- candidate 创建
- 人工批准
- canary、staged、broad、full 分阶段推进
- 拒绝
- 回滚

## 8. 规划运行时优先的防护

除了代码修复，AION 还会输出运行时防护计划，例如：

- gateway block
- WAF rule
- feature flag 变更
- dependency pin
- code patch follow-up

它的默认倾向是先做 containment，再做代码 rollout。

## 9. 自我进化循环：漂移检测与持续学习

AION 实现了一个持续自我改进的闭环：

### 漂移检测

`aion snapshot` 在某一时刻捕获安全指纹（文件哈希 + 安全事件 + 健康评分）。
`aion drift` 将实时状态与该基线对比，识别回退并计算健康变化量。

| 状态 | 默认位置 |
|---|---|
| 快照 | `.aion/snapshots/` |

健康评分是一个 0.0–1.0 的指标：1.0 表示无已知漏洞；
数值越低表明事件严重程度和数量相对仓库规模越高。

### 知识库

每一次成功修复都会以模式的形式记录到知识库。随着时间推移，引擎会针对每种问题类型
和修复策略积累历史成功率。这些成功率会在修复时计算**置信度加成**，使已充分理解的
问题类型得到更高置信度的处理。

| 状态 | 默认位置 |
|---|---|
| 修复模式 | `.aion/knowledge/patterns.json` |

### 监控模式

`aion watch` 实现了外层循环：轮询 → 检测漂移 → 自动修复 → 记录 → 刷新基线。
每次迭代都会利用知识库提升修复置信度。使用 `aion status` 可查看累积的状态。

## 10. 当前边界

当前版本停留在本地控制面决策和持久化 artifact 这一层。真实生产队列、部署系统、
WAF API、feature flag provider 和自动发布系统，仍然是这些接口之上的适配工作。
