# 路线图

这份路线图反映的是 AION 当前已经落地的能力，以及从“本地控制面原型”继续走向
“生产级自愈系统”还需要补的部分。

## 当前状态

仓库目前已经具备：

- 基于仓库上下文和 Semgrep 初筛的 Python 安全扫描
- 确定性修复 artifact 和独立验证链路
- 带 repair record 和指标统计的修复评估
- 面向单事件、事件队列、inbox 和 webhook 的 sandbox 编排
- 支持批准、分阶段推进、拒绝和回滚的 release candidate
- 面向 containment 优先的运行时防护计划
- 用于自我进化的漂移检测、知识库和持续 watch 循环
- 知识库置信度加成已接入 policy engine，闭合自进化反馈回路

## 已完成阶段

### Phase 0：可信基础 — 已在 v1.0.0 发布

- finding 已升级为结构化 incident。
- repair、verify、orchestrate、release 共用统一 JSON 模型。
- fixture 已能覆盖 incident 生命周期闭环。

### Phase 1：自动修复闭环 — 已在 v1.0.0 发布

- 首批支持的问题类型已经具备确定性修复。
- 验证链路包含语法检查、Semgrep 重扫、断言和可选 sandbox 命令。
- `repair`、`verify`、`run-incident` 已形成完整本地闭环。

### Phase 2：自我验证与学习 — 已在 v1.0.0 发布

- repair attempt 可以持久化为审计记录。
- `repair-eval` 可以计算修复成功率、验证通过率、误修率和回滚率。
- 失败结果已经能被记录下来，用于后续规则和策略迭代。

### Phase 3：预生产自治原型 — 已在 v1.0.0 发布

- orchestrator 已支持 JSON 事件、队列、inbox 和 webhook 入口。
- policy gating 会决定 incident 是否允许进入自动 sandbox 修复。
- 仓级 sandbox 已支持执行项目级验证命令。
- release candidate 管理已覆盖批准和 staged rollout 决策。

### Phase 4：自进化引擎 — 已在 v1.1.0 发布

- **漂移检测**：`snapshot` 保存某时刻的安全状态基线；`drift` 将当前代码库与已保存
  的基线进行比对，输出新增 incident、已解决 incident、回归文件和数字健康值变化量。
- **知识库**：每次成功修复都会以 `RepairPattern` 的形式持久化到
  `.aion/knowledge/patterns.json`；基于历史成功率计算的置信度加成由 `PolicyEngine`
  在自动修复阈值判断前应用，从而闭合了自进化反馈回路。
- **持续 watch 循环**：`watch` 按照可配置的时间间隔轮询目标目录，对新检测到的
  incident 自动修复，并在每次成功修复后刷新基线。
- **引擎状态仪表盘**：`status` 在一个视图中展示所有已保存的快照和完整知识库摘要。
- **LLM 提供商支持扩展**：新增 Gemini 和 Azure OpenAI，与原有的 Anthropic、OpenAI
  并列支持，并可通过环境变量自动检测提供商。

## 下一步

### Phase 5：生产适配器

接下来的主要工作已经不再是核心数据模型，而是集成层：

- 面向真实事件源的鉴权 webhook 和消息队列适配器
- 面向发布、回滚和 rollout telemetry 的部署系统适配器
- 面向 WAF、gateway、feature flag 的执行适配器
- 与外部审批和审计系统的联动
- 更智能的仓库测试选择，而不只是固定命令列表

## 指导原则

AION 的默认策略仍然是保守的。相比“黑盒自动化”，它优先选择确定性 artifact、
可审计状态和可回退的发布决策。
