"""
Diagnostic: filtered base rules and the correlation rules referencing them must share the
same filtered detection semantics.

These tests trace the actual objects along collection reference resolution, filter application
and backend conversion, and compute expected results from a small event set instead of only
comparing object identities or query strings:

* two correlations share one filtered base rule, base alerts and correlation alerts are both
  published (generate: true),
* the same collection is converted repeatedly and merged, which must not stack filter
  conditions,
* a processing pipeline keeps renaming fields after the filter was applied.
"""

from datetime import datetime, timedelta, timezone

import pytest

from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.matching.event import Event, EventLogSource
from sigma.matching.matcher import SigmaMatcher
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

COLLECTION_YAML = """
title: Base Rule
name: base_rule
id: 11111111-1111-1111-1111-111111111111
logsource:
    product: test
detection:
    selection:
        CommandLine|contains: "malicious"
    condition: selection
---
title: Whitelist filter
name: whitelist_filter
id: 22222222-2222-2222-2222-222222222222
logsource:
    product: test
filter:
    rules:
        - base_rule
    selection:
        User: "svc_backup"
    condition: not selection
---
title: Correlation A
name: corr_a
id: 33333333-3333-3333-3333-333333333333
correlation:
    type: event_count
    rules:
        - base_rule
    generate: true
    timespan: 5m
    condition:
        gte: 3
---
title: Correlation B
name: corr_b
id: 44444444-4444-4444-4444-444444444444
correlation:
    type: temporal
    rules:
        - base_rule
        - other_rule
    generate: true
    timespan: 5m
---
title: Other Rule
name: other_rule
id: 55555555-5555-5555-5555-555555555555
logsource:
    product: test
detection:
    selection:
        CommandLine|contains: "recon"
    condition: selection
"""


@pytest.fixture
def collection():
    return SigmaCollection.from_yaml(COLLECTION_YAML)


@pytest.fixture
def event_set():
    """Small event set with known expected outcome:

    * 3 malicious events from the whitelisted account svc_backup: excluded everywhere.
    * 3 malicious events from attacker: 3 base alerts, corr_a fires once (gte 3).
    * 1 recon event from attacker: together with the base alerts corr_b fires once.
    * 1 benign event: no alert at all.
    """
    logsource = EventLogSource(product="test")
    t0 = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)
    return [
        *(
            Event(
                data={"CommandLine": "run malicious --dumper", "User": "svc_backup"},
                logsource=logsource,
                timestamp=t0 + timedelta(seconds=i),
            )
            for i in range(3)
        ),
        *(
            Event(
                data={"CommandLine": "run malicious --dumper", "User": "attacker"},
                logsource=logsource,
                timestamp=t0 + timedelta(seconds=10 + i),
            )
            for i in range(3)
        ),
        Event(
            data={"CommandLine": "recon --scan", "User": "attacker"},
            logsource=logsource,
            timestamp=t0 + timedelta(seconds=13),
        ),
        Event(
            data={"CommandLine": "notepad.exe", "User": "attacker"},
            logsource=logsource,
            timestamp=t0 + timedelta(seconds=20),
        ),
    ]


def matches_by_rule(matches, name):
    return [m for m in matches if m.rule.name == name]


def test_correlations_use_filtered_detection_semantics(collection, event_set):
    """Both correlations referencing the filtered base rule must only see filtered events."""
    # Reference resolution points the correlations at the very same filtered rule object
    base_rule = collection["base_rule"]
    for corr_name in ("corr_a", "corr_b"):
        corr = collection[corr_name]
        referenced = {ref.reference: ref.rule for ref in corr.referenced_rules}
        assert referenced["base_rule"] is base_rule
    assert base_rule._output  # generate: true keeps base alerts published

    # Backend conversion embeds the filtered detection into both correlation queries
    queries = TextQueryTestBackend().convert(collection)
    assert len(queries) == 4  # base, corr_a, other_rule, corr_b
    assert queries[0] == 'CommandLine contains "malicious" and not User="svc_backup"'
    assert queries[1].startswith(queries[0])  # corr_a aggregates the filtered base query
    assert (
        'subsearch { CommandLine contains "malicious" and not User="svc_backup" | set event_type="base_rule" }'
        in queries[3]  # corr_b subsearch uses the filtered base query
    )

    # Event-set evaluation: whitelisted events must not contribute to any alert
    matches = SigmaMatcher(collection).bulk_match(event_set)
    base_matches = matches_by_rule(matches, "base_rule")
    corr_a_matches = matches_by_rule(matches, "corr_a")
    corr_b_matches = matches_by_rule(matches, "corr_b")

    assert len(base_matches) == 3  # only the 3 legit malicious events
    assert all(m.events[0].data["User"] == "attacker" for m in base_matches)

    assert len(corr_a_matches) == 1  # gte 3 reached by the 3 legit events only
    assert len(corr_a_matches[0].events) == 3
    assert len(corr_b_matches) == 1  # base_rule + other_rule fired within the window

    for correlation_match in corr_a_matches + corr_b_matches:
        assert all(event.data["User"] != "svc_backup" for event in correlation_match.events)


def test_repeated_conversion_does_not_stack_filters(collection):
    """Converting the same collection repeatedly must not re-apply filters or references."""
    base_rule = collection["base_rule"]
    conditions = list(base_rule.detection.condition)
    detections = set(base_rule.detection.detections.keys())

    backend = TextQueryTestBackend()
    first = backend.convert(collection)
    second = backend.convert(collection)

    assert first == second
    assert base_rule.detection.condition == conditions
    assert set(base_rule.detection.detections.keys()) == detections
    assert base_rule.detection.condition[0].count("_filt_") == 1  # filter applied once
    # reference resolution runs on every convert() but must stay idempotent
    assert sorted(r.name for r in base_rule._backreferences) == ["corr_a", "corr_b"]


def test_merge_does_not_stack_filters(collection):
    """Merging an already filtered collection must not apply its filters a second time."""
    base_rule = collection["base_rule"]
    conditions = list(base_rule.detection.condition)

    merged = SigmaCollection.merge([collection])
    merged_base_rule = merged["base_rule"]

    assert merged_base_rule.detection.condition == conditions
    assert merged_base_rule.detection.condition[0].count("_filt_") == 1
    queries = TextQueryTestBackend().convert(merged)
    assert queries[0] == 'CommandLine contains "malicious" and not User="svc_backup"'
    assert queries[0].count('not User="svc_backup"') == 1


def test_pipeline_field_mapping_after_filter(collection, event_set):
    """A pipeline renaming fields after filter application renames the filter detections
    as well, in the base query and in the correlation subqueries alike."""
    pipeline = ProcessingPipeline(
        [
            ProcessingItem(
                FieldMappingTransformation({"User": "AccountName", "CommandLine": "Cmd"})
            )
        ]
    )
    queries = TextQueryTestBackend(processing_pipeline=pipeline).convert(collection)
    assert queries[0] == 'Cmd contains "malicious" and not AccountName="svc_backup"'
    assert queries[1].startswith(queries[0])
    assert (
        'subsearch { Cmd contains "malicious" and not AccountName="svc_backup" | set event_type="base_rule" }'
        in queries[3]
    )

    # The matcher applies the same pipeline: renamed events still produce the expected alerts
    renamed_events = [
        Event(
            data={"Cmd" if k == "CommandLine" else "AccountName" if k == "User" else k: v
                  for k, v in event.data.items()},
            logsource=event.logsource,
            timestamp=event.timestamp,
        )
        for event in event_set
    ]
    fresh_collection = SigmaCollection.from_yaml(COLLECTION_YAML)
    matches = SigmaMatcher(fresh_collection, pipeline=pipeline).bulk_match(renamed_events)
    assert len(matches_by_rule(matches, "base_rule")) == 3
    corr_matches = matches_by_rule(matches, "corr_a") + matches_by_rule(matches, "corr_b")
    assert len(corr_matches) == 2
    assert all(
        event.data["AccountName"] != "svc_backup"
        for match in corr_matches
        for event in match.events
    )
