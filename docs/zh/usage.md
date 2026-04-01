# 使用

## 扫描整个仓库

```bash
uv run aion scan ./path/to/project
```

## 只扫描已知的 AI 生成文件

```bash
uv run aion scan ./path/to/project \
  --ai-generated ./path/to/project/generated_file.py
```

## 切换到 OpenAI

```bash
uv run aion scan ./path/to/project --provider openai
```

## 输出 JSON

```bash
uv run aion scan ./path/to/project --output json
```

## 输出详细调试信息

```bash
uv run aion scan ./path/to/project --verbose
```

修复与验证闭环：

```bash
uv run aion repair ./path/to/file.py \
  --context-file ./context.json \
  --artifact-path ./artifact.json \
  --record-path ./repair-record.json

uv run aion verify --artifact-path ./artifact.json

uv run aion run-incident ./path/to/file.py \
  --context-file ./context.json \
  --record-path ./incident-record.json \
  --output json

uv run aion repair-eval ./tests/fixtures \
  --records-dir ./repair-records \
  --output json

uv run aion process-event ./event.json \
  --result-path ./orchestration.json \
  --output json

uv run aion process-event-queue ./events.json \
  --results-dir ./queue-results \
  --output json

uv run aion enqueue-event ./event.json \
  --inbox-root ./.aion/inbox

uv run aion list-inbox \
  --inbox-root ./.aion/inbox \
  --status pending

uv run aion process-inbox \
  --inbox-root ./.aion/inbox \
  --output json

uv run aion serve-webhook \
  --inbox-root ./.aion/inbox \
  --host 127.0.0.1 \
  --port 8080

uv run aion create-release-candidate ./.aion/inbox/results/<event>.json \
  --releases-root ./.aion/releases

uv run aion approve-release <candidate-id> \
  --approver alice \
  --releases-root ./.aion/releases

uv run aion advance-release <candidate-id> \
  --releases-root ./.aion/releases

uv run aion rollback-release <candidate-id> \
  --reason "failed canary metrics" \
  --releases-root ./.aion/releases

uv run aion plan-defense ./.aion/inbox/results/<event>.json \
  --output json
```

当前首版自治能力只生成补丁 artifact 并在本地验证，不会直接原地改写生产文件。
`repair-eval` 会批量运行确定性修复流水线，并输出修复成功率、验证通过率、误修率和回滚率。
`process-event` 是当前控制平面原型入口：它接收事件 payload，做策略门控，并只在 sandbox 工作区里执行获批修复。
`process-event-queue` 接收一个事件数组，批量执行编排，并为每个事件落盘结果，同时输出队列级指标。
inbox 命令提供了持久化事件队列 `.aion/inbox`，让运行时告警可以先入队，再按批次增量处理。
`serve-webhook` 会暴露 `POST /events`，把收到的事件直接写入 inbox，供后续异步编排处理。
release 命令会在 `.aion/releases` 下保存 staged rollout candidate，并支持批准、分阶段推进、拒绝和回滚。
`plan-defense` 会输出运行时优先的防护动作，比如 gateway block、WAF rule、feature flag、dependency pin，以及后续 code patch。

`.aion.yaml` 里的编排配置示例：

```yaml
auto_repair_issue_types:
  - raw_sqlite_query
  - hardcoded_secret
auto_repair_min_confidence: 0.90
sandbox_mode: repository
sandbox_verification_commands:
  - python -m pytest tests/unit
auto_approve_verified_fixes: false
rollback_on_verification_failure: true
```

配置了 `sandbox_verification_commands` 后，AION 会在 staged workspace 内执行这些项目级验证命令，并记录每条命令的退出码、stdout/stderr，以及最终发布建议：
- `approved_for_rollout`：sandbox 验证通过且启用了自动批准
- `rollback`：验证失败且启用了失败即回滚
- `needs_human_review`：其余情况

`--verbose` 会把上下文提取结果、Semgrep 结果、fallback 原因和 token 估算输出到 stderr。

## 推荐使用流程

1. 指向一个仓库或一个已生成文件。
2. 让工具自动识别候选 Python 文件。
3. 查看 AI 文件识别和 `semgrep` 可用性的 warning。
4. 重点阅读 context-aware 的问题解释和修复建议。
