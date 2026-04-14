"""Stub-path tests for harvester and drafter.

These cover everything that runs without an API key.  Live-path tests are
out of scope here — the SDK layer is exercised when the loop runs live.
"""
from __future__ import annotations

from research import config as cfg
from research import drafter, harvester


def _stub_settings() -> cfg.LoopSettings:
    return cfg.LoopSettings(dry_run=True)


def test_fixture_signals_distill_cleanly():
    settings = _stub_settings()
    raw = harvester.load_offline_fixture()
    signals = harvester.distill_signals(raw, settings=settings)
    assert signals
    attack_classes = {s["attack_class"] for s in signals}
    # fixture is constructed to hit three classes
    assert "malicious-payload" in attack_classes
    assert "prompt-injection-in-description" in attack_classes
    assert "maintainer-sockpuppet" in attack_classes


def test_drafter_handles_prompt_injection_signal():
    signals = [{
        "title": "prompt-injection README",
        "attack_class": "prompt-injection-in-description",
        "example_name": "helpful-llm-tools",
        "advisory_ids": ["GHSA-FAKE-0002"],
    }]
    spec = drafter.draft(signals, settings=_stub_settings())
    assert spec.detector_id != "NONE"
    assert spec.kind == "description_keyword"
    assert "ignore previous" in [k.lower() for k in spec.keywords]
    assert spec.avt_class == "AVT-D1-01"


def test_drafter_handles_sockpuppet_signal():
    signals = [{
        "title": "disposable email",
        "attack_class": "maintainer-sockpuppet",
        "example_name": "x",
        "advisory_ids": ["A"],
    }]
    spec = drafter.draft(signals, settings=_stub_settings())
    assert spec.kind == "maintainer_email_regex"
    assert spec.pattern is not None


def test_drafter_handles_empty_signals():
    spec = drafter.draft([], settings=_stub_settings())
    assert spec.detector_id == "NONE"


def test_harvest_end_to_end_dry_run():
    """Full harvest pipeline — fixture -> distill -> signals."""
    signals = harvester.harvest(settings=_stub_settings())
    assert len(signals) >= 1
    for s in signals:
        assert "attack_class" in s
        assert "advisory_ids" in s
