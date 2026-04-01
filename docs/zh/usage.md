# 使用

## 前置条件

- 运行 `scan` 前先设置 `OPENAI_API_KEY` 或 `ANTHROPIC_API_KEY`
- 如果希望统一策略和 sandbox 默认值，请在目标仓库根目录放置 `.aion.yaml`
- 需要机器可读输出时使用 `--output json`

## 1. 扫描仓库

```bash
uv run aion scan ./path/to/project
```

只扫描你已经确认是 AI 生成的文件：

```bash
uv run aion scan ./path/to/project \
  --ai-generated ./path/to/project/generated_file.py
```

切换 provider 或输出 JSON：

```bash
uv run aion scan ./path/to/project --provider openai --output json
```

输出上下文提取、fallback 原因和 Semgrep 细节：

```bash
uv run aion scan ./path/to/project --verbose
```

## 2. 生成并验证修复 artifact

创建确定性 patch artifact，并把审计记录一起落盘：

```bash
uv run aion repair ./path/to/file.py \
  --context-file ./context.json \
  --artifact-path ./artifact.json \
  --record-path ./repair-record.json
```

验证已有 artifact：

```bash
uv run aion verify --artifact-path ./artifact.json
```

对单个文件运行完整 incident 流程：

```bash
uv run aion run-incident ./path/to/file.py \
  --context-file ./context.json \
  --record-path ./incident-record.json \
  --output json
```

在 fixture 上评估确定性修复质量：

```bash
uv run aion repair-eval ./tests/fixtures \
  --records-dir ./repair-records \
  --output json
```

## 3. 在 sandbox 中编排事件

处理单个事件：

```bash
uv run aion process-event ./event.json \
  --result-path ./orchestration.json \
  --output json
```

批量处理事件数组：

```bash
uv run aion process-event-queue ./events.json \
  --results-dir ./queue-results \
  --output json
```

典型事件 payload：

```json
{
  "event_id": "runtime-001",
  "event_type": "runtime_alert",
  "target_file": "/absolute/path/to/service.py",
  "metadata": {
    "repo_root": "/absolute/path/to/repo",
    "context_file": "/absolute/path/to/context.json"
  }
}
```

当前版本支持的事件类型：

- `code_scan`
- `runtime_alert`
- `dependency_alert`

## 4. 使用持久化 inbox 和 webhook

把事件写入文件型 inbox：

```bash
uv run aion enqueue-event ./event.json \
  --inbox-root ./.aion/inbox
```

查看待处理或已处理事件：

```bash
uv run aion list-inbox \
  --inbox-root ./.aion/inbox \
  --status pending
```

处理当前所有 pending 事件：

```bash
uv run aion process-inbox \
  --inbox-root ./.aion/inbox \
  --output json
```

启动 webhook 接收器：

```bash
uv run aion serve-webhook \
  --inbox-root ./.aion/inbox \
  --host 127.0.0.1 \
  --port 8080
```

webhook 会接收 `POST /events`，并把合法 payload 写入 inbox。

## 5. 管理 staged rollout

从成功的 orchestration result 创建 release candidate：

```bash
uv run aion create-release-candidate ./.aion/inbox/results/<event>.json \
  --releases-root ./.aion/releases
```

查看当前 candidate：

```bash
uv run aion list-releases --releases-root ./.aion/releases
```

批准并向下一阶段推进：

```bash
uv run aion approve-release <candidate-id> \
  --approver alice \
  --releases-root ./.aion/releases

uv run aion advance-release <candidate-id> \
  --releases-root ./.aion/releases
```

拒绝或回滚：

```bash
uv run aion reject-release <candidate-id> \
  --approver alice \
  --reason "review failed" \
  --releases-root ./.aion/releases

uv run aion rollback-release <candidate-id> \
  --reason "failed canary metrics" \
  --releases-root ./.aion/releases
```

## 6. 规划运行时防护动作

基于 orchestration result 生成运行时防护建议：

```bash
uv run aion plan-defense ./.aion/inbox/results/<event>.json --output json
```

当前 defense planner 可输出：

- gateway block
- WAF rule
- feature flag 动作
- dependency pin 建议
- code patch follow-up 动作

## 运行说明

- 当前版本生成的是 patch artifact，不会直接原地改写生产文件。
- `sandbox_verification_commands` 只会在 staged workspace 中执行，不会在你的工作树里直接运行。
- `process-event` 和 inbox 处理会自动从事件仓库根目录加载 `.aion.yaml`。
- `repair-eval` 会输出修复成功率、验证通过率、误修率和回滚率。
