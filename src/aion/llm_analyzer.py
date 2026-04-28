from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Literal

from .models import ContextProfile, Finding, LLMScanResponse, SemgrepFinding

LLMProvider = Literal["anthropic", "openai", "gemini", "azure", "deepseek", "qwen"]


class LLMAnalyzerError(RuntimeError):
    pass


def _extract_error_message(raw: str) -> str:
    """Return a concise error message, stripping instructor's retry XML when present."""
    # instructor wraps all retry attempts in <last_exception>…</last_exception>
    match = re.search(r"<last_exception>\s*(.*?)\s*</last_exception>", raw, re.DOTALL)
    last_exc = match.group(1).strip() if match else raw

    # Try to extract the human-readable 'message' value from the API error dict
    msg_match = re.search(r"'message':\s*'([^']+)'", last_exc)
    if msg_match:
        return msg_match.group(1)

    return last_exc


class LLMAnalyzer:
    def __init__(
        self,
        api_key: str,
        model: str,
        provider: LLMProvider = "anthropic",
        max_chunk_lines: int = 200,
        overlap_lines: int = 50,
        verbose: bool = False,
    ):
        self.api_key = api_key
        self.model = model
        self.provider = provider
        self.max_chunk_lines = max_chunk_lines
        self.overlap_lines = overlap_lines
        self.verbose = verbose

    def analyze(
        self,
        target: Path,
        context_profile: ContextProfile,
        semgrep_findings: list[SemgrepFinding],
        fallback_signals: list[str] | None = None,
        console=None,
    ) -> list[Finding]:
        try:
            source = target.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            raise LLMAnalyzerError(f"failed to read {target}: {exc}") from exc

        client = self._create_client()
        chunks = self._chunk_source(source)
        findings: list[Finding] = []
        for chunk in chunks:
            prompt = self._build_prompt(
                target=target,
                chunk_text=chunk["text"],
                start_line=chunk["start_line"],
                end_line=chunk["end_line"],
                context_profile=context_profile,
                semgrep_findings=semgrep_findings,
                fallback_signals=fallback_signals or [],
            )
            if self.verbose and console is not None:
                console.print("[bold]LLM prompt[/bold]")
                console.print(prompt)
            try:
                response = self._create_completion(client, prompt)
            except Exception as exc:  # noqa: BLE001
                raise LLMAnalyzerError(_extract_error_message(str(exc))) from exc

            for finding in response.findings:
                findings.append(
                    Finding(
                        issue=finding.issue,
                        severity=finding.severity,
                        line=self._remap_line(chunk["start_line"], finding.line),
                        context_gap=finding.context_gap,
                        fix=finding.fix,
                        semgrep_rule=finding.semgrep_rule,
                    )
                )
        return self._deduplicate(findings)

    def _create_client(self):
        try:
            import instructor
        except ImportError as exc:
            raise LLMAnalyzerError("instructor is not installed") from exc

        if self.provider == "anthropic":
            try:
                from anthropic import Anthropic
            except ImportError as exc:
                raise LLMAnalyzerError("anthropic is not installed") from exc
            return instructor.from_anthropic(Anthropic(api_key=self.api_key))

        if self.provider == "openai":
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise LLMAnalyzerError("openai is not installed") from exc
            return instructor.from_openai(OpenAI(api_key=self.api_key))

        if self.provider == "gemini":
            try:
                import google.generativeai as genai
            except ImportError as exc:
                raise LLMAnalyzerError(
                    "google-generativeai is not installed; run: pip install google-generativeai"
                ) from exc
            genai.configure(api_key=self.api_key)
            return instructor.from_gemini(
                client=genai.GenerativeModel(model_name=self.model),
                mode=instructor.Mode.GEMINI_JSON,
            )

        if self.provider == "azure":
            try:
                from openai import AzureOpenAI
            except ImportError as exc:
                raise LLMAnalyzerError("openai is not installed") from exc
            endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "")
            if not endpoint:
                raise LLMAnalyzerError(
                    "AZURE_OPENAI_ENDPOINT is not set. "
                    "Export it before running, for example: "
                    "export AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com"
                )
            return instructor.from_openai(
                AzureOpenAI(
                    api_key=self.api_key,
                    api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01"),
                    azure_endpoint=endpoint,
                )
            )

        if self.provider == "deepseek":
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise LLMAnalyzerError("openai is not installed") from exc
            return instructor.from_openai(
                OpenAI(
                    api_key=self.api_key,
                    base_url="https://api.deepseek.com/v1",
                )
            )

        if self.provider == "qwen":
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise LLMAnalyzerError("openai is not installed") from exc
            return instructor.from_openai(
                OpenAI(
                    api_key=self.api_key,
                    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
                )
            )

        raise LLMAnalyzerError(f"unsupported provider: {self.provider}")

    def _create_completion(self, client, prompt: str) -> LLMScanResponse:
        if self.provider == "anthropic":
            return client.messages.create(
                model=self.model,
                max_tokens=1800,
                temperature=0,
                response_model=LLMScanResponse,
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
            )

        if self.provider in ("openai", "azure", "deepseek", "qwen"):
            return client.chat.completions.create(
                model=self.model,
                max_completion_tokens=1800,
                response_model=LLMScanResponse,
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
            )

        if self.provider == "gemini":
            return client.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                response_model=LLMScanResponse,
            )

        raise LLMAnalyzerError(f"unsupported provider: {self.provider}")

    def estimate_tokens(self, target: Path, context_profile: ContextProfile) -> int:
        source = target.read_text(encoding="utf-8", errors="ignore")
        payload = json.dumps(context_profile.summary_payload(), ensure_ascii=False)
        total_chars = len(source) + len(payload)
        return max(total_chars // 4, 1)

    def _build_prompt(
        self,
        target: Path,
        chunk_text: str,
        start_line: int,
        end_line: int,
        context_profile: ContextProfile,
        semgrep_findings: list[SemgrepFinding],
        fallback_signals: list[str],
    ) -> str:
        semgrep_summary = [
            {
                "rule": finding.check_id,
                "line": finding.line,
                "severity": finding.severity,
                "message": finding.message,
            }
            for finding in semgrep_findings
            if start_line <= finding.line <= end_line
        ]
        return (
            "You are reviewing AI-generated Python code for security issues.\n"
            "Focus on context-blindness: places where the code ignores established project patterns.\n"
            "Return only structured findings matching the response schema.\n\n"
            f"Target file: {target}\n"
            f"Chunk line range: {start_line}-{end_line}\n"
            f"Project context summary: {json.dumps(context_profile.summary_payload(), ensure_ascii=False)}\n"
            f"Semgrep findings in this chunk: {json.dumps(semgrep_summary, ensure_ascii=False)}\n\n"
            f"Fallback risk signals: {json.dumps(fallback_signals, ensure_ascii=False)}\n\n"
            "Rules:\n"
            "- Report only concrete security issues.\n"
            "- line must be relative to this chunk, not the whole file.\n"
            "- context_gap must explain what the AI likely did not know about the project.\n"
            "- If project context implies ORM/auth/rate-limit usage, mention the exact project pattern being bypassed.\n"
            "- If fallback risk signals are present, investigate them directly even if Semgrep found nothing.\n"
            "- Do not treat an empty Semgrep result as evidence that the code is safe.\n"
            "- Keep fixes actionable and specific.\n\n"
            "Code chunk:\n"
            f"{chunk_text}"
        )

    def _chunk_source(self, source: str) -> list[dict[str, object]]:
        lines = source.splitlines()
        if len(lines) <= self.max_chunk_lines:
            return [
                {
                    "text": source,
                    "start_line": 1,
                    "end_line": max(len(lines), 1),
                }
            ]

        chunks: list[dict[str, object]] = []
        step = self.max_chunk_lines - self.overlap_lines
        start = 0
        while start < len(lines):
            end = min(start + self.max_chunk_lines, len(lines))
            chunks.append(
                {
                    "text": "\n".join(lines[start:end]),
                    "start_line": start + 1,
                    "end_line": end,
                }
            )
            if end >= len(lines):
                break
            start += step
        return chunks

    def _remap_line(self, chunk_start_line: int, reported_line: int) -> int:
        return max(chunk_start_line + reported_line - 1, 1)

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[int, str, str]] = set()
        unique: list[Finding] = []
        for finding in sorted(findings, key=lambda item: (item.line, item.issue, item.severity)):
            key = (finding.line, finding.issue, finding.severity)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique
