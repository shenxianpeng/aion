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

## 当前实现中已经完成的阶段

### Phase 0：可信基础

- finding 已升级为结构化 incident。
- repair、verify、orchestrate、release 共用统一 JSON 模型。
- fixture 已能覆盖 incident 生命周期闭环。

### Phase 1：自动修复闭环

- 首批支持的问题类型已经具备确定性修复。
- 验证链路包含语法检查、Semgrep 重扫、断言和可选 sandbox 命令。
- `repair`、`verify`、`run-incident` 已形成完整本地闭环。

### Phase 2：自我验证与学习

- repair attempt 可以持久化为审计记录。
- `repair-eval` 可以计算修复成功率、验证通过率、误修率和回滚率。
- 失败结果已经能被记录下来，用于后续规则和策略迭代。

### Phase 3：预生产自治原型

- orchestrator 已支持 JSON 事件、队列、inbox 和 webhook 入口。
- policy gating 会决定 incident 是否允许进入自动 sandbox 修复。
- 仓级 sandbox 已支持执行项目级验证命令。
- release candidate 管理已覆盖批准和 staged rollout 决策。

## 下一步

### Phase 4：生产适配器

接下来的主要工作已经不再是核心数据模型，而是集成层：

- 面向真实事件源的鉴权 webhook 和消息队列适配器
- 面向发布、回滚和 rollout telemetry 的部署系统适配器
- 面向 WAF、gateway、feature flag 的执行适配器
- 与外部审批和审计系统的联动
- 更智能的仓库测试选择，而不只是固定命令列表

## 指导原则

AION 的默认策略仍然是保守的。相比“黑盒自动化”，它优先选择确定性 artifact、
可审计状态和可回退的发布决策。
