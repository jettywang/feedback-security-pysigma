"""Tests for structured filter suppression provenance.

The provenance features live in :mod:`sigma.suppression` and are populated by
:class:`sigma.filters.SigmaFilter`.  These tests cover:

* the provenance follows the actually applied condition nodes (including nodes
  below a ``NOT`` and nodes of stacked filters),
* filters that do not match a rule never appear in the output,
* one filter applied to several rules gets an independent source per rule,
* the sources survive when a filtered rule is referenced by a correlation rule,
* detection semantics are unchanged and independent filters commute.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.conditions import ConditionAND, ConditionNOT
from sigma.filters import SigmaFilter
from sigma.matching import Event, EventLogSource, SigmaMatcher
from sigma.suppression import (
    RULES_ANY,
    SuppressionSource,
    suppression_provenance,
    suppression_subtrees,
    suppression_trace,
)

from .test_conversion_base import test_backend

RULE_YAML = """
title: Failed login
id: 6f3e2987-db24-4c78-a860-b4f4095a7095
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 4625
    condition: selection
"""

FILTER_YAML = """
title: Filter Administrator account
id: 11111111-1111-1111-1111-111111111111
logsource:
    category: process_creation
    product: windows
filter:
  rules:
    - 6f3e2987-db24-4c78-a860-b4f4095a7095
  selection:
      User|startswith: 'adm_'
  condition: not selection
"""


def _apply(filter_yaml: str = FILTER_YAML, rule_yaml: str = RULE_YAML):
    collection = SigmaCollection.from_yaml(rule_yaml)
    sigma_filter = SigmaFilter.from_yaml(filter_yaml)
    collection.apply_filters([sigma_filter])
    return collection, sigma_filter


def test_provenance_records_matched_filter_only():
    collection, _ = _apply()
    rule = collection.rules[0]

    sources = suppression_provenance(rule)
    assert len(sources) == 1
    source = sources[0]
    assert isinstance(source, SuppressionSource)
    assert source.filter_title == "Filter Administrator account"
    assert source.filter_id == "11111111-1111-1111-1111-111111111111"
    assert source.matched_rules == ["6f3e2987-db24-4c78-a860-b4f4095a7095"]
    assert source.filter_condition == "not selection"
    assert source.prefix.startswith("_filt_")
    assert source.rule_title == "Failed login"
    assert source.rule_id == "6f3e2987-db24-4c78-a860-b4f4095a7095"
    # The filter is the only suppression and the rule's own detection has none.
    assert rule.detection.detections["selection"].suppression is None
    filter_detection = next(
        detection
        for name, detection in rule.detection.detections.items()
        if name.startswith("_filt_")
    )
    assert filter_detection.suppression is source


def test_provenance_follows_not_condition_nodes():
    collection, _ = _apply()
    rule = collection.rules[0]
    condition_tree = rule.detection.parsed_condition[0].parsed

    subtrees = suppression_subtrees(condition_tree)
    # The leaf (User startswith adm_) and the NOT above it are both reported;
    # the root AND mixes rule and filter nodes and must not be reported.
    assert all(source.filter_title == "Filter Administrator account" for _, source in subtrees)
    node_types = {type(node) for node, _ in subtrees}
    assert ConditionNOT in node_types
    assert ConditionAND not in node_types

    trace = suppression_trace(rule)
    rendered_nodes = [entry["condition_node"] for entry in trace]
    assert {"NOT": [{"field": "User", "value": "adm_*"}]} in rendered_nodes
    assert {"field": "User", "value": "adm_*"} in rendered_nodes
    # Every trace entry points back to the same filter input.
    assert {entry["source"]["filter_id"] for entry in trace} == {
        "11111111-1111-1111-1111-111111111111"
    }


def test_unmatched_filter_leaves_no_provenance(test_backend):
    # Wrong logsource and an unknown rule reference: nothing must be applied.
    unmatched_filter = SigmaFilter.from_yaml(
        FILTER_YAML.replace("product: windows", "product: linux").replace(
            "6f3e2987-db24-4c78-a860-b4f4095a7095",
            "00000000-0000-0000-0000-000000000000",
        )
    )
    collection = SigmaCollection.from_yaml(RULE_YAML)
    collection.apply_filters([unmatched_filter])

    rule = collection.rules[0]
    assert suppression_provenance(rule) == []
    assert suppression_trace(rule) == []
    assert not any(name.startswith("_filt_") for name in rule.detection.detections)
    assert test_backend.convert(collection) == ["EventID=4625"]


def test_stacked_filters_both_traced(test_backend):
    first = SigmaFilter.from_yaml(
        FILTER_YAML.replace("Filter Administrator account", "Filter admin").replace(
            "11111111-1111-1111-1111-111111111111", "11111111-1111-1111-1111-111111111111"
        )
    )
    second = SigmaFilter.from_yaml("""
title: Filter service accounts
id: 22222222-2222-2222-2222-222222222222
logsource:
    category: process_creation
    product: windows
filter:
  rules: any
  selection:
      User|startswith: 'srv_'
  condition: not selection
""")

    collection = SigmaCollection.from_yaml(RULE_YAML)
    collection.apply_filters([first, second])
    rule = collection.rules[0]

    sources = suppression_provenance(rule)
    assert [source.filter_title for source in sources] == [
        "Filter admin",
        "Filter service accounts",
    ]
    assert sources[1].matched_rules == RULES_ANY
    assert test_backend.convert(collection) == [
        'EventID=4625 and not User startswith "adm_" and not User startswith "srv_"'
    ]

    subtrees = suppression_subtrees(rule.detection.parsed_condition[0].parsed)
    assert {source.filter_id for _, source in subtrees} == {
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    }


def test_one_filter_matching_several_rules_gets_independent_sources(test_backend):
    rules_yaml = """
title: Rule 1
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: a.exe
    condition: selection
---
title: Rule 2
id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: b.exe
    condition: selection
"""
    sigma_filter = SigmaFilter.from_yaml("""
title: Filter SYSTEM
id: 33333333-3333-3333-3333-333333333333
logsource:
    category: process_creation
    product: windows
filter:
  rules: any
  selection:
      User: SYSTEM
  condition: not selection
""")
    collection = SigmaCollection.from_yaml(rules_yaml)
    collection.apply_filters([sigma_filter])

    assert len(collection.rules) == 2
    sources_per_rule = [suppression_provenance(rule) for rule in collection.rules]
    assert all(len(sources) == 1 for sources in sources_per_rule)
    first_source, second_source = (sources[0] for sources in sources_per_rule)
    # Independent application per rule: distinct prefixes and distinct rule metadata.
    assert first_source is not second_source
    assert first_source.prefix != second_source.prefix
    assert first_source.rule_title == "Rule 1"
    assert second_source.rule_title == "Rule 2"
    # The copied detections are not shared between rules.
    first_detection = next(
        detection
        for name, detection in collection.rules[0].detection.detections.items()
        if name.startswith("_filt_")
    )
    second_detection = next(
        detection
        for name, detection in collection.rules[1].detection.detections.items()
        if name.startswith("_filt_")
    )
    assert first_detection is not second_detection
    assert test_backend.convert(collection) == [
        'Image="a.exe" and not User="SYSTEM"',
        'Image="b.exe" and not User="SYSTEM"',
    ]


def test_provenance_keeps_input_locations(tmp_path: Path):
    rule_path = tmp_path / "rule.yml"
    filter_path = tmp_path / "filter.yml"
    rule_path.write_text(RULE_YAML)
    filter_path.write_text(FILTER_YAML)

    collection = SigmaCollection.load_ruleset([rule_path, filter_path])
    rule = collection.rules[0]
    source = suppression_provenance(rule)[0]

    assert source.filter_source is not None
    assert source.rule_source is not None
    assert source.filter_source.path == filter_path
    assert source.rule_source.path == rule_path

    serialized = suppression_trace(rule)[0]["source"]
    assert serialized["filter_source"]["path"] == str(filter_path)
    assert serialized["rule_source"]["path"] == str(rule_path)


def test_correlation_rule_keeps_filter_provenance_on_referenced_rule(test_backend):
    rules_yaml = """
title: Failed logon
name: failed_logon
id: df0841c0-9846-4e9f-ad8a-7df91571771b
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons
status: test
correlation:
    type: event_count
    rules:
        - failed_logon
    group-by:
        - TargetUserName
    timespan: 5m
    condition:
        gte: 10
"""
    sigma_filter = SigmaFilter.from_yaml(
        FILTER_YAML.replace(
            "6f3e2987-db24-4c78-a860-b4f4095a7095",
            "df0841c0-9846-4e9f-ad8a-7df91571771b",
        )
    )
    collection = SigmaCollection.from_yaml(rules_yaml)
    collection.apply_filters([sigma_filter])

    base_rule = collection["failed_logon"]
    sources = suppression_provenance(base_rule)
    assert len(sources) == 1
    assert sources[0].filter_title == "Filter Administrator account"

    converted = test_backend.convert(collection)
    assert len(converted) == 1
    assert 'EventID=4625 and not User startswith "adm_"' in converted[0]
    assert "aggregate window=5min" in converted[0]


def test_suppression_semantics_trigger_vs_excluded_event():
    collection, _ = _apply()
    logsource = EventLogSource(category="process_creation", product="windows")
    timestamp = datetime.now(tz=timezone.utc)
    triggering_event = Event(
        timestamp,
        logsource,
        {"EventID": 4625, "User": "jdoe"},
    )
    excluded_event = Event(
        timestamp,
        logsource,
        {"EventID": 4625, "User": "adm_bob"},
    )

    with SigmaMatcher(collection) as matcher:
        assert [match.rule.title for match in matcher.match(triggering_event)] == ["Failed login"]
        assert matcher.match(excluded_event) == []


def test_independent_filters_commute_semantically():
    admin_filter = SigmaFilter.from_yaml("""
title: Filter admin accounts
id: 11111111-1111-1111-1111-111111111111
logsource:
    category: process_creation
    product: windows
filter:
  rules: any
  selection:
      User|startswith: 'adm_'
  condition: not selection
""")
    host_filter = SigmaFilter.from_yaml("""
title: Filter jump hosts
id: 22222222-2222-2222-2222-222222222222
logsource:
    category: process_creation
    product: windows
filter:
  rules: any
  selection:
      ComputerName|startswith: 'JUMP-'
  condition: not selection
""")

    def build(order: list[SigmaFilter]) -> SigmaCollection:
        collection = SigmaCollection.from_yaml(RULE_YAML)
        collection.apply_filters(order)
        return collection

    order_ab = build([admin_filter, host_filter])
    order_ba = build([host_filter, admin_filter])

    logsource = EventLogSource(category="process_creation", product="windows")
    timestamp = datetime.now(tz=timezone.utc)
    events = {
        "trigger": Event(
            timestamp, logsource, {"EventID": 4625, "User": "jdoe", "ComputerName": "WS-01"}
        ),
        "admin": Event(
            timestamp, logsource, {"EventID": 4625, "User": "adm_bob", "ComputerName": "WS-01"}
        ),
        "jump": Event(
            timestamp, logsource, {"EventID": 4625, "User": "jdoe", "ComputerName": "JUMP-03"}
        ),
    }

    def match_results(collection: SigmaCollection) -> dict[str, bool]:
        with SigmaMatcher(collection) as matcher:
            return {name: bool(matcher.match(event)) for name, event in events.items()}

    assert match_results(order_ab) == match_results(order_ba)
    assert match_results(order_ab) == {
        "trigger": True,
        "admin": False,
        "jump": False,
    }
    # Provenance set is identical regardless of order; only application order changes.
    titles_ab = [source.filter_title for source in suppression_provenance(order_ab.rules[0])]
    titles_ba = [source.filter_title for source in suppression_provenance(order_ba.rules[0])]
    assert (
        set(titles_ab)
        == set(titles_ba)
        == {
            "Filter admin accounts",
            "Filter jump hosts",
        }
    )
    assert titles_ab == list(reversed(titles_ba))


def test_provenance_disappears_when_filter_nodes_are_dropped():
    from sigma.processing.conditions import IncludeFieldCondition
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import DropDetectionItemTransformation

    collection, _ = _apply()
    rule = collection.rules[0]
    pipeline = ProcessingPipeline(
        [
            ProcessingItem(
                DropDetectionItemTransformation(),
                field_name_conditions=[IncludeFieldCondition(fields=["User"])],
                identifier="drop-user",
            )
        ]
    )
    pipeline.apply(rule)

    # The filter detection still exists as an empty shell, but its condition
    # nodes are gone, so no suppression source can be traced anymore.
    assert suppression_provenance(rule) == []
    assert suppression_trace(rule) == []


def test_to_dict_roundtrip_contains_provenance_fields():
    collection, _ = _apply()
    source = suppression_provenance(collection.rules[0])[0]
    serialized = source.to_dict()

    assert serialized["filter_title"] == "Filter Administrator account"
    assert serialized["filter_condition"] == "not selection"
    assert serialized["prefix"] == source.prefix
    assert serialized["matched_rules"] == ["6f3e2987-db24-4c78-a860-b4f4095a7095"]
    # Rule to_dict/from_dict still works and the filter never alters original logic data.
    rule_dict = collection.rules[0].to_dict()
    assert rule_dict["detection"]["selection"] == {"EventID": 4625}
    rebuilt = SigmaCollection.from_yaml(RULE_YAML).rules[0]
    assert rebuilt.detection.condition == ["selection"]
