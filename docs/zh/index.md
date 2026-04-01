# AION 概览

AION 是面向 Python 服务的自主代码免疫系统。它从上下文感知安全扫描开始，
继续进入确定性修复、sandbox 验证、事件编排、分阶段发布控制，以及运行时优先的防护计划。

## 当前版本已实现

| 领域 | 已实现能力 |
|---|---|
| 检测 | 仓库上下文提取、Semgrep 初筛、fallback heuristic、可选 LLM 解释 |
| 修复 | 针对原始 SQLite 拼接、硬编码 secret、缺失鉴权装饰器的确定性 patch artifact |
| 验证 | 语法检查、Semgrep 重扫、内建断言、sandbox 内项目命令 |
| 控制面 | JSON 事件接入、持久化 inbox、队列处理、webhook 入口 |
| 发布 | release candidate 创建、批准、分阶段推进、拒绝、回滚 |
| 防护 | gateway、WAF、feature flag、dependency、code follow-up 防护计划 |

## 运行模型

1. 扫描仓库或接收事件。
2. 把发现结果提升为结构化 incident。
3. 生成 patch artifact，而不是直接改动 live 仓库。
4. 在 sandbox 中 staged 修复并验证。
5. 把结果持久化为 inbox item、orchestration record 或 release candidate。
6. 生成 rollout 建议和运行时防护动作。

## AION 适合什么场景

- 审查 AI 生成或新引入 Python 代码是否偏离项目约定
- 搭建本地“自主修复控制面”原型
- 在接入真实生产适配器前验证策略门控修复流程
- 以 JSON artifact 的形式保留可审计的修复、验证和发布状态

## 当前还不做什么

- 不会直接在线热修生产代码
- 不会直接推送到部署系统、WAF 提供方或 feature flag 服务
- 当前版本只支持 Python

## 继续阅读

- [安装](installation.md)
- [使用](usage.md)
- [配置](configuration.md)
- [工作原理](how-it-works.md)
