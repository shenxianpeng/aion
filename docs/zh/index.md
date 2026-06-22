---
hide:
  - navigation
  - toc
---

<div class="aion-home">
  <section class="aion-home__hero">
    <div class="aion-home__eyebrow">面向 Python 的可验证安全自动修复</div>
    <h1 class="aion-home__title">
      扫描 Python 仓库。
      <span>开出你敢信任的安全修复。</span>
    </h1>
    <p class="aion-home__lede">
      AION 会扫描 Python 仓库中一组高置信度的安全问题，为每个问题生成确定性补丁，
      在隔离环境中完成验证，只为通过验证的修复开 Pull Request。无法证明安全的修复，
      只上报供人工复核，绝不擅自改动你的代码。
    </p>
    <div class="aion-home__actions">
      <a class="md-button md-button--primary" href="usage/">快速开始</a>
      <a class="md-button" href="how-it-works/">了解原理</a>
    </div>
    <div class="aion-home__signal-grid">
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Detect</div>
        <div class="aion-signal-card__value">Semgrep + Context + LLM</div>
      </div>
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Repair</div>
        <div class="aion-signal-card__value">确定性补丁</div>
      </div>
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Verify</div>
        <div class="aion-signal-card__value">语法 + AST + Semgrep</div>
      </div>
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Ship</div>
        <div class="aion-signal-card__value">已验证的 Pull Request</div>
      </div>
    </div>
  </section>

  <section class="aion-home__manifesto">
    <p>
      刻意做小。目标是一个你敢让它在仓库里无人值守运行的工具，而不是一个需要你运维的平台。
    </p>
  </section>

  <section class="aion-card-grid">
    <article class="aion-panel">
      <h2>它做什么</h2>
      <ul>
        <li>基于仓库上下文与 Semgrep 初筛的 Python 安全扫描</li>
        <li>针对 secret、原始 SQL、不安全的 YAML/eval、命令注入、弱哈希的确定性补丁</li>
        <li>验证门：每个补丁必须能解析、通过 AST 断言、并经受 Semgrep 重扫</li>
        <li>只为达到 <code>verified_fix</code> 的修复开 Pull Request</li>
      </ul>
    </article>
    <article class="aion-panel">
      <h2>工作流程</h2>
      <ol>
        <li>提取仓库画像（ORM、鉴权、数据库模式）作为上下文。</li>
        <li>用 Semgrep、启发式规则和可选 LLM 检测问题。</li>
        <li>为支持的问题类型生成确定性补丁。</li>
        <li>在隔离环境中验证补丁。</li>
        <li>为每个已验证修复开 PR，其余上报复核。</li>
      </ol>
    </article>
    <article class="aion-panel">
      <h2>它适合什么</h2>
      <ul>
        <li>自动修复 Python 服务中高置信度的安全问题</li>
        <li>审查 AI 生成代码是否偏离仓库真实约定</li>
        <li>用快照与 watch 循环检测安全漂移</li>
      </ul>
    </article>
    <article class="aion-panel">
      <h2>它不做什么</h2>
      <ul>
        <li>不在线热修生产代码，只产出补丁和 PR</li>
        <li>不是运行时控制平面——不接管 WAF、网关或部署系统</li>
        <li>当前版本只支持 Python</li>
      </ul>
    </article>
  </section>
</div>
