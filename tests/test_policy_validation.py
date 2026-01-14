import pytest

from faramesh.server.policy_engine import PolicyEngine


def test_policy_validation_rejects_bad_structure(tmp_path):
    bad_policy = tmp_path / "bad.yaml"
    bad_policy.write_text("not-a-map")
    with pytest.raises(ValueError):
        PolicyEngine(str(bad_policy))


def test_policy_validation_requires_effect(tmp_path):
    bad_policy = tmp_path / "bad_effect.yaml"
    bad_policy.write_text(
        """
rules:
  - match:
      tool: "http"
      op: "*"
"""
    )
    with pytest.raises(ValueError):
        PolicyEngine(str(bad_policy))


def test_policy_validation_accepts_examples(tmp_path):
    good_policy = tmp_path / "good.yaml"
    good_policy.write_text(
        """
rules:
  - match:
      tool: "http"
      op: "*"
    allow: true
"""
    )
    engine = PolicyEngine(str(good_policy))
    assert engine.policy_version() == "yaml"
