---
hide:
  - navigation
  - toc
---

<div class="aion-home">
  <section class="aion-home__hero">
    <div class="aion-home__eyebrow">verified security auto-fixes for python</div>
    <h1 class="aion-home__title">
      Scan Python repos.
      <span>Open security fixes you can trust.</span>
    </h1>
    <p class="aion-home__lede">
      AION scans a Python repository for a focused set of high-confidence
      security issues, generates a deterministic patch for each one, verifies it
      in isolation, and opens a pull request only for fixes that pass. If a fix
      can't be proven safe, it is reported for review instead of touching your code.
    </p>
    <div class="aion-home__actions">
      <a class="md-button md-button--primary" href="usage/">Get started</a>
      <a class="md-button" href="how-it-works/">See how it works</a>
    </div>
    <div class="aion-home__signal-grid">
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Detect</div>
        <div class="aion-signal-card__value">Semgrep + Context + LLM</div>
      </div>
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Repair</div>
        <div class="aion-signal-card__value">Deterministic Patches</div>
      </div>
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Verify</div>
        <div class="aion-signal-card__value">Syntax + AST + Semgrep</div>
      </div>
      <div class="aion-signal-card">
        <div class="aion-signal-card__label">Ship</div>
        <div class="aion-signal-card__value">Verified Pull Requests</div>
      </div>
    </div>
  </section>

  <section class="aion-home__manifesto">
    <p>
      Intentionally small. The goal is a tool you can trust to run unattended on
      your repository — not a platform you have to operate.
    </p>
  </section>

  <section class="aion-card-grid">
    <article class="aion-panel">
      <h2>What it does</h2>
      <ul>
        <li>Context-aware Python scanning with repository profiling and Semgrep triage</li>
        <li>Deterministic patches for secrets, raw SQL, unsafe YAML/eval, shell injection, and weak hashing</li>
        <li>A verification gate: every patch must parse, satisfy an AST assertion, and survive a Semgrep re-scan</li>
        <li>Pull requests opened only for fixes that reach <code>verified_fix</code></li>
      </ul>
    </article>
    <article class="aion-panel">
      <h2>How it works</h2>
      <ol>
        <li>Profile the repository (ORM, auth, DB patterns) for context.</li>
        <li>Detect incidents with Semgrep, heuristics, and optional LLM.</li>
        <li>Generate a deterministic patch artifact for supported issue types.</li>
        <li>Verify the patch in isolation.</li>
        <li>Open a PR for each verified fix; report the rest for review.</li>
      </ol>
    </article>
    <article class="aion-panel">
      <h2>What it's for</h2>
      <ul>
        <li>Auto-remediating high-confidence security issues in Python services</li>
        <li>Reviewing AI-generated code against repository-specific conventions</li>
        <li>Detecting security drift over time with snapshots and a watch loop</li>
      </ul>
    </article>
    <article class="aion-panel">
      <h2>What it does not do</h2>
      <ul>
        <li>No in-place production hot patching; it produces patches and PRs</li>
        <li>Not a runtime control plane — no WAF, gateway, or deploy integration</li>
        <li>Python-only by design</li>
      </ul>
    </article>
  </section>
</div>
