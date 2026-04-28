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


def test_create_client_deepseek(monkeypatch) -> None:
    """_create_client initializes a deepseek client with the correct base_url."""
    try:
        import openai  # noqa: F401
    except ImportError:
        return  # skip if openai not available

    from unittest import mock

    monkeypatch.setattr("instructor.from_openai", mock.MagicMock(return_value="fake-client"))
    analyzer = LLMAnalyzer(api_key="sk-deepseek", model="deepseek-chat", provider="deepseek")

    client = analyzer._create_client()
    assert client == "fake-client"


def test_create_client_qwen(monkeypatch) -> None:
    """_create_client initializes a qwen client with the correct base_url."""
    try:
        import openai  # noqa: F401
    except ImportError:
        return

    from unittest import mock

    monkeypatch.setattr("instructor.from_openai", mock.MagicMock(return_value="fake-client-qwen"))
    analyzer = LLMAnalyzer(api_key="sk-qwen", model="qwen-plus", provider="qwen")

    client = analyzer._create_client()
    assert client == "fake-client-qwen"


def test_create_client_unsupported_provider_raises() -> None:
    """_create_client raises for an unknown provider."""
    analyzer = LLMAnalyzer(api_key="test", model="test-model", provider="unknown")  # type: ignore[arg-type]
    try:
        analyzer._create_client()
        assert False, "Expected LLMAnalyzerError"
    except Exception as exc:
        assert "unsupported provider" in str(exc)


def test_create_completion_deepseek(monkeypatch) -> None:
    """_create_completion uses chat.completions for deepseek."""
    from unittest import mock

    fake_client = mock.MagicMock()
    fake_response = mock.MagicMock()
    fake_client.chat.completions.create.return_value = fake_response

    analyzer = LLMAnalyzer(api_key="sk-test", model="deepseek-chat", provider="deepseek")
    result = analyzer._create_completion(fake_client, "test prompt")
    assert result == fake_response
    fake_client.chat.completions.create.assert_called_once()


def test_create_completion_qwen(monkeypatch) -> None:
    """_create_completion uses chat.completions for qwen."""
    from unittest import mock

    fake_client = mock.MagicMock()
    fake_response = mock.MagicMock()
    fake_client.chat.completions.create.return_value = fake_response

    analyzer = LLMAnalyzer(api_key="sk-test", model="qwen-plus", provider="qwen")
    result = analyzer._create_completion(fake_client, "test prompt")
    assert result == fake_response
    fake_client.chat.completions.create.assert_called_once()


def test_llm_analyzer_accepts_deepseek_provider() -> None:
    """LLMAnalyzer accepts 'deepseek' as a valid provider."""
    analyzer = LLMAnalyzer(api_key="sk-test", model="deepseek-chat", provider="deepseek")
    assert analyzer.provider == "deepseek"
    assert analyzer.model == "deepseek-chat"


def test_llm_analyzer_accepts_qwen_provider() -> None:
    """LLMAnalyzer accepts 'qwen' as a valid provider."""
    analyzer = LLMAnalyzer(api_key="sk-test", model="qwen-plus", provider="qwen")
    assert analyzer.provider == "qwen"
    assert analyzer.model == "qwen-plus"
