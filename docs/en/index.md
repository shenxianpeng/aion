---
hide:
  - navigation
  - toc
---

<div class="aion-home">
  <section class="aion-home__hero">
    <div class="aion-home__eyebrow">autonomous software civilization</div>
    <h1 class="aion-home__title">
      Build code that refuses to decay.
      <span>Operate software as a living system.</span>
    </h1>
    <p class="aion-home__lede">
      AION is the control plane for code immortality. It detects structural drift,
      synthesizes deterministic repairs, verifies them in isolation, and prepares
      rollout plus runtime containment before a hotfix becomes human toil.
    </p>
    <div class="aion-home__actions">
      <a class="md-button md-button--primary" href="usage/">Start the loop</a>
      <a class="md-button" href="how-it-works/">See the architecture</a>
    </div>
    <div class="aion-home__signal-grid">
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Detect</div>
        <div class="aion-signal-card__value">Semgrep + Context + LLM</div>
      </div>
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Repair</div>
        <div class="aion-signal-card__value">Deterministic Patch Artifacts</div>
      </div>
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Verify</div>
        <div class="aion-signal-card__value">Sandbox + Project Commands</div>
      </div>
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Defend</div>
        <div class="aion-signal-card__value">Release + Containment Decisions</div>
      </div>
    </div>
  </section>

  <section class="aion-home__manifesto">
    <p>
      The goal is not faster maintenance. The goal is to end maintenance as a
      default human activity.
    </p>
  </section>

  <section class="aion-card-grid">
    <article class="aion-panel">
      <h2>What ships now</h2>
      <ul>
        <li>Context-aware Python scanning with repository profiling and Semgrep triage</li>
        <li>Deterministic remediation for raw SQLite interpolation, secrets, and auth drift</li>
        <li>Sandbox verification with assertions, Semgrep re-scan, and project commands</li>
        <li>Inbox, queue, webhook, release, rollback, and defense planning control-plane flows</li>
      </ul>
    </article>
    <article class="aion-panel">
      <h2>Operating model</h2>
      <ol>
        <li>Ingest a repository scan or runtime event.</li>
        <li>Upgrade findings into incidents and remediation plans.</li>
        <li>Emit a patch artifact instead of mutating the live repository.</li>
        <li>Verify the artifact inside a file or repository sandbox.</li>
        <li>Persist the result as orchestration state and rollout intent.</li>
      </ol>
    </article>
    <article class="aion-panel">
      <h2>What AION is for</h2>
      <ul>
        <li>Evaluating AI-generated code against repository-specific conventions</li>
        <li>Prototyping autonomous repair loops with policy gates</li>
        <li>Building auditable remediation records for future production adapters</li>
      </ul>
    </article>
    <article class="aion-panel">
      <h2>Current boundary</h2>
      <ul>
        <li>No in-place production hot patching</li>
        <li>No direct push into external deploy, WAF, or feature-flag systems</li>
        <li>Python-only in the current release</li>
      </ul>
    </article>
  </section>
</div>
