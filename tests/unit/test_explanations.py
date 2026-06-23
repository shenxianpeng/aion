from aion.explanations import EXPLANATIONS, Explanation, explanation_for
from aion.repair import IncidentDetector


def test_explanation_for_known_issue_type() -> None:
    explanation = explanation_for("hardcoded_secret")
    assert isinstance(explanation, Explanation)
    assert "os.getenv" in explanation.fix
    assert explanation.risk
    assert explanation.behavior_note


def test_explanation_for_unknown_issue_type_returns_none() -> None:
    assert explanation_for("not_a_real_issue_type") is None


def test_every_supported_issue_type_has_an_explanation() -> None:
    """Each issue type the detector can emit must have a plain-language explanation.

    This guards against adding a new fix without explaining it to reviewers.
    """
    supported = set(IncidentDetector._SUPPORTED_INCIDENTS)
    explained = set(EXPLANATIONS)
    missing = supported - explained
    assert not missing, f"Missing explanations for: {sorted(missing)}"


def test_explanations_have_non_empty_fields() -> None:
    for issue_type, explanation in EXPLANATIONS.items():
        assert explanation.risk.strip(), f"{issue_type} has empty risk"
        assert explanation.fix.strip(), f"{issue_type} has empty fix"
        assert explanation.behavior_note.strip(), f"{issue_type} has empty behavior_note"
