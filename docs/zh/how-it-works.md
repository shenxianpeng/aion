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

## 9. 当前边界

当前版本停留在本地控制面决策和持久化 artifact 这一层。真实生产队列、部署系统、
WAF API、feature flag provider 和自动发布系统，仍然是这些接口之上的适配工作。
