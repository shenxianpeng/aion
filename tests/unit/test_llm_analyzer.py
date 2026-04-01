from aion.llm_analyzer import LLMAnalyzer
from aion.models import Finding


def test_chunk_source_splits_large_files() -> None:
    analyzer = LLMAnalyzer(api_key="test", model="claude-3-5-sonnet-latest", max_chunk_lines=4, overlap_lines=1)
    source = "\n".join(f"line {index}" for index in range(1, 9))

    chunks = analyzer._chunk_source(source)

    assert len(chunks) == 3
    assert chunks[0]["start_line"] == 1
    assert chunks[0]["end_line"] == 4
    assert chunks[1]["start_line"] == 4
    assert chunks[1]["end_line"] == 7
    assert chunks[2]["start_line"] == 7
    assert chunks[2]["end_line"] == 8


def test_deduplicate_keeps_unique_findings() -> None:
    analyzer = LLMAnalyzer(api_key="test", model="claude-3-5-sonnet-latest")
    findings = [
        Finding(
            issue="SQL injection risk",
            severity="high",
            line=10,
            context_gap="Project uses SQLAlchemy sessions.",
            fix="Use parameterized queries.",
            semgrep_rule="rule-1",
        ),
        Finding(
            issue="SQL injection risk",
            severity="high",
            line=10,
            context_gap="Project uses SQLAlchemy sessions.",
            fix="Use parameterized queries.",
            semgrep_rule="rule-1",
        ),
        Finding(
            issue="Hardcoded secret",
            severity="medium",
            line=20,
            context_gap="Project stores secrets in env vars.",
            fix="Load the secret from the environment.",
            semgrep_rule="rule-2",
        ),
    ]

    deduped = analyzer._deduplicate(findings)

    assert len(deduped) == 2
