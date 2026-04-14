"""End-to-end smoke test — the whole loop in dry-run mode produces an artifact."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from research import config as cfg
from research import loop


@pytest.fixture
def tmp_settings(tmp_path: Path, monkeypatch) -> cfg.LoopSettings:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    return cfg.LoopSettings(
        dry_run=True,
        corpus_path=cfg.CORPUS_PATH,   # reuse repo seed corpus
        artifacts_dir=artifacts,
    )


def test_tick_produces_artifact(tmp_settings: cfg.LoopSettings):
    result = loop.tick(settings=tmp_settings)
    assert "artifact_path" in result
    path = Path(result["artifact_path"])
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["dry_run"] is True
    assert "spec" in data
    assert "evaluation" in data
    assert "deterministic_gate" in data
    # The gate may accept or reject depending on detector/corpus — both are
    # valid outcomes.  Only require that the loop ran to completion.
    assert isinstance(data["deterministic_gate"]["passed"], bool)
    if data["deterministic_gate"]["passed"]:
        assert data["reviewer_verdict"] is not None
        assert data["reviewer_verdict"]["decision"] in ("accept", "reject", "needs_work")


def test_tick_reaches_accept_on_seed_corpus(tmp_settings):
    """The seed corpus + stub drafter should yield at least one ACCEPT.

    The sockpuppet email detector in the stub has precision 1.0 on the
    seed corpus (every disposable-email entry is labeled malicious), so
    the gate + stub reviewer should accept it.
    """
    result = loop.tick(settings=tmp_settings)
    data = json.loads(Path(result["artifact_path"]).read_text())
    assert data["spec"]["kind"] == "maintainer_email_regex"
    assert data["deterministic_gate"]["passed"] is True
    assert data["reviewer_verdict"]["decision"] == "accept"


def test_tick_artifact_filename_encodes_decision(tmp_settings):
    result = loop.tick(settings=tmp_settings)
    path = Path(result["artifact_path"])
    # filename shape: <timestamp>__<decision>__<detector_id>.json
    parts = path.stem.split("__")
    assert len(parts) == 3
    assert parts[1] in ("accept", "reject", "needs_work", "skipped")
