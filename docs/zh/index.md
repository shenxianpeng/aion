---
hide:
  - navigation
  - toc
---

<div class="aion-home">
  <section class="aion-home__hero">
    <div class="aion-home__eyebrow">autonomous software civilization</div>
    <h1 class="aion-home__title">
      让代码拒绝衰亡。
      <span>把软件系统当作可持续进化的生命体来运营。</span>
    </h1>
    <p class="aion-home__lede">
      AION 是“代码永生”的控制平面。它感知结构漂移，生成确定性修复，
      在隔离环境中完成验证，并在人工介入之前先产出 rollout 与运行时防护决策。
    </p>
    <div class="aion-home__actions">
      <a class="md-button md-button--primary" href="usage/">开始闭环</a>
      <a class="md-button" href="how-it-works/">查看架构</a>
    </div>
    <div class="aion-home__signal-grid">
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Detect</div>
        <div class="aion-signal-card__value">Semgrep + Context + LLM</div>
      </div>
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Repair</div>
        <div class="aion-signal-card__value">确定性 Patch Artifact</div>
      </div>
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Verify</div>
        <div class="aion-signal-card__value">Sandbox + 项目命令验证</div>
      </div>
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Defend</div>
        <div class="aion-signal-card__value">发布与 Containment 决策</div>
      </div>
    </div>
  </section>

  <section class="aion-home__manifesto">
    <p>
      目标不是把维护做得更快，而是让“维护”不再成为人类的默认劳动。
    </p>
  </section>

  <section class="aion-card-grid">
    <article class="aion-panel">
      <h2>当前已具备</h2>
      <ul>
        <li>基于仓库上下文和 Semgrep 初筛的 Python 安全扫描</li>
        <li>针对 SQLite 拼接、secret、鉴权漂移的确定性修复</li>
        <li>结合断言、Semgrep 重扫和项目命令的 sandbox 验证</li>
        <li>inbox、queue、webhook、release、rollback、defense 组成的控制面闭环</li>
      </ul>
    </article>
    <article class="aion-panel">
      <h2>运行模型</h2>
      <ol>
        <li>接收仓库扫描结果或运行时事件。</li>
        <li>把 finding 升级为 incident 与 remediation plan。</li>
        <li>生成 patch artifact，而不是直接改写 live 仓库。</li>
        <li>在文件级或仓级 sandbox 中完成验证。</li>
        <li>把结果持久化为编排状态与发布意图。</li>
      </ol>
    </article>
    <article class="aion-panel">
      <h2>AION 适合什么</h2>
      <ul>
        <li>审查 AI 生成代码是否偏离仓库真实约定</li>
        <li>搭建带策略门控的自主修复原型</li>
        <li>为未来生产适配器积累可审计的修复与验证记录</li>
      </ul>
    </article>
    <article class="aion-panel">
      <h2>当前边界</h2>
      <ul>
        <li>不会直接在线热修生产代码</li>
        <li>不会直接接管外部部署、WAF 或 feature flag 系统</li>
        <li>当前版本只支持 Python</li>
      </ul>
    </article>
  </section>
</div>
