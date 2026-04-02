from aion.llm_analyzer import LLMAnalyzer, _extract_error_message
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


def test_extract_error_message_strips_instructor_retry_xml() -> None:
    raw = (
        "\n\n<failed_attempts>\n\n"
        "<exception>\n Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error',"
        " 'message': 'Your credit balance is too low to access the Anthropic API.'}, 'request_id': 'req_1'}\n</exception>\n"
        "<completion>\n None\n</completion>\n\n"
        "</failed_attempts>\n\n"
        "<last_exception>\n Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error',"
        " 'message': 'Your credit balance is too low to access the Anthropic API.'}, 'request_id': 'req_1'}\n</last_exception>"
    )

    result = _extract_error_message(raw)

    assert result == "Your credit balance is too low to access the Anthropic API."


def test_extract_error_message_with_last_exception_only() -> None:
    raw = (
        "\n\n<last_exception>\n Error code: 400 - {'type': 'error',"
        " 'error': {'type': 'invalid_request_error', 'message': 'Quota exceeded.'},"
        " 'request_id': 'req_2'}\n</last_exception>"
    )

    result = _extract_error_message(raw)

    assert result == "Quota exceeded."


def test_extract_error_message_plain_string_unchanged() -> None:
    raw = "instructor is not installed"

    result = _extract_error_message(raw)

    assert result == "instructor is not installed"
