import pytest

from sigma.collection import SigmaCollection
from sigma.compare import (
    ComparisonResult,
    Relation,
    compare_rules,
    event_matches_rule,
)
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.processing.pipeline import ProcessingPipeline

RULE_V1 = """
title: Suspicious Shell Process Spawned
id: 8f3c2f10-0000-4000-8000-000000000001
status: test
description: Detects invocation of suspicious shell interpreters.
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image:
            - cmd.exe
            - powershell.exe
    condition: selection
level: medium
"""

RULE_V2_ADDED_VALUE = """
title: Suspicious Shell Process Spawned
id: 8f3c2f10-0000-4000-8000-000000000001
status: test
description: Detects invocation of suspicious shell interpreters.
modified: 2026-11-01
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image:
            - cmd.exe
            - powershell.exe
            - pwsh.exe
    condition: selection
level: medium
"""

RULE_V2_TIGHTENED = """
title: Suspicious Shell Process Spawned
id: 8f3c2f10-0000-4000-8000-000000000001
status: test
description: Detects invocation of suspicious shell interpreters.
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image:
            - cmd.exe
            - powershell.exe
    context:
        ParentImage: explorer.exe
    condition: selection and context
level: medium
"""

RULE_V2_DESCRIPTION = """
title: Suspicious Shell Process Spawned
id: 8f3c2f10-0000-4000-8000-000000000001
status: test
description: Detects invocation of suspicious shell interpreters, e.g. from phishing documents.
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image:
            - cmd.exe
            - powershell.exe
    condition: selection
level: medium
"""

PIPELINE = """
name: review-pipeline
transformations:
    - id: image-rename
      type: field_name_mapping
      mapping:
          Image: ProcessName
          ParentImage: ParentProcessName
"""


@pytest.fixture
def pipeline():
    return ProcessingPipeline.from_yaml(PIPELINE)


def test_added_value_expands():
    result = compare_rules(RULE_V1, RULE_V2_ADDED_VALUE)
    assert result.relation == Relation.EXPANDS
    assert result.distinguishing_event == {"Image": "pwsh.exe"}
    assert result.event_matches_old is False
    assert result.event_matches_new is True
    # evidence is independently re-verifiable
    assert not event_matches_rule(RULE_V1, result.distinguishing_event)
    assert event_matches_rule(RULE_V2_ADDED_VALUE, result.distinguishing_event)


def test_tightened_condition_narrows():
    result = compare_rules(RULE_V1, RULE_V2_TIGHTENED)
    assert result.relation == Relation.NARROWS
    event = result.distinguishing_event
    assert event is not None
    assert event_matches_rule(RULE_V1, event)
    assert not event_matches_rule(RULE_V2_TIGHTENED, event)


def test_description_only_is_equivalent_with_metadata():
    result = compare_rules(RULE_V1, RULE_V2_DESCRIPTION)
    assert result.relation == Relation.EQUIVALENT
    assert result.distinguishing_event is None
    changed_fields = {change.field for change in result.metadata_changes}
    assert changed_fields == {"description"}


def test_identical_rules_are_equivalent():
    result = compare_rules(RULE_V1, RULE_V1)
    assert result.relation == Relation.EQUIVALENT
    assert result.metadata_changes == []


def test_field_mapping_applied_before_comparison(pipeline):
    result = compare_rules(RULE_V1, RULE_V2_ADDED_VALUE, pipeline)
    assert result.relation == Relation.EXPANDS
    # the distinguishing event uses the mapped field name
    assert result.distinguishing_event == {"ProcessName": "pwsh.exe"}
    assert event_matches_rule(RULE_V2_ADDED_VALUE, result.distinguishing_event, pipeline)


def test_regex_modifier_is_unknown():
    rule_re = RULE_V1.replace("Image:", "Image|re:").replace(
        "- cmd.exe\n            - powershell.exe", "- '^.*(cmd|powershell)\\.exe$'"
    )
    result = compare_rules(RULE_V1, rule_re)
    assert result.relation == Relation.UNKNOWN
    assert any("modifier" in reason for reason in result.unsupported)


def test_contains_modifier_is_unknown():
    result = compare_rules(RULE_V1, RULE_V1.replace("Image:", "Image|contains:"))
    assert result.relation == Relation.UNKNOWN


def test_all_modifier_is_unknown():
    result = compare_rules(RULE_V1, RULE_V1.replace("Image:", "Image|all:"))
    assert result.relation == Relation.UNKNOWN


def test_wildcard_value_is_unknown():
    result = compare_rules(RULE_V1, RULE_V1.replace("- cmd.exe", "- cmd*.exe"))
    assert result.relation == Relation.UNKNOWN
    assert any("wildcard" in reason for reason in result.unsupported)


def test_keyword_detection_is_unknown():
    keyword_rule = """
title: Keywords
logsource:
    product: windows
    category: process_creation
detection:
    keywords:
        - mimikatz
    condition: keywords
"""
    result = compare_rules(RULE_V1, keyword_rule)
    assert result.relation == Relation.UNKNOWN


def test_not_condition_is_unknown():
    rule_not = """
title: With NOT
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image: cmd.exe
    filter:
        User: SYSTEM
    condition: selection and not filter
"""
    result = compare_rules(RULE_V1, rule_not)
    assert result.relation == Relation.UNKNOWN


def test_patterned_selector_is_unknown():
    rule_selector = """
title: Selector
logsource:
    product: windows
    category: process_creation
detection:
    selection_1:
        Image: cmd.exe
    selection_2:
        Image: powershell.exe
    condition: 1 of selection_*
"""
    result = compare_rules(RULE_V1, rule_selector)
    assert result.relation == Relation.UNKNOWN


def test_one_of_them_is_supported():
    rule_them = """
title: Them
logsource:
    product: windows
    category: process_creation
detection:
    a:
        Image: cmd.exe
    b:
        Image: powershell.exe
    condition: 1 of them
"""
    result = compare_rules(RULE_V1, rule_them)
    assert result.relation == Relation.EQUIVALENT


def test_correlation_rule_is_unknown():
    correlation_yaml = """
title: Base
id: 11111111-1111-1111-1111-111111111111
logsource:
    product: windows
detection:
    sel:
        Image: cmd.exe
    condition: sel
---
title: Correlation
correlation:
    type: event_count
    rules:
        - 11111111-1111-1111-1111-111111111111
    timespan: 5m
    condition:
        gte: 10
"""
    correlation = [
        rule
        for rule in SigmaCollection.from_yaml(correlation_yaml).rules
        if isinstance(rule, SigmaCorrelationRule)
    ][0]
    result = compare_rules(correlation, correlation)
    assert result.relation == Relation.UNKNOWN
    assert "correlation rule" in result.unsupported


def test_differing_logsource_is_unknown():
    result = compare_rules(
        RULE_V1, RULE_V1.replace("category: process_creation", "category: process_access")
    )
    assert result.relation == Relation.UNKNOWN
    assert "log source" in result.reason


def test_incomparable_rules_are_unknown_with_evidence():
    result = compare_rules(RULE_V1, RULE_V1.replace("- powershell.exe", "- pwsh.exe"))
    assert result.relation == Relation.UNKNOWN
    assert "incomparable" in result.reason


def test_distributive_restructuring_is_equivalent():
    rule_a = """
title: A
logsource:
    product: windows
detection:
    s1:
        Image: cmd.exe
    s2:
        Image: powershell.exe
    s3:
        User: SYSTEM
    condition: (s1 or s2) and s3
"""
    rule_b = """
title: B
logsource:
    product: windows
detection:
    s1:
        Image: cmd.exe
        User: SYSTEM
    s2:
        Image: powershell.exe
        User: SYSTEM
    condition: s1 or s2
"""
    assert compare_rules(rule_a, rule_b).relation == Relation.EQUIVALENT


def test_removed_value_narrows():
    result = compare_rules(RULE_V2_ADDED_VALUE, RULE_V1)
    assert result.relation == Relation.NARROWS
    assert result.distinguishing_event == {"Image": "pwsh.exe"}


def test_event_matches_rule_rejects_unsupported():
    rule_re = RULE_V1.replace("Image:", "Image|re:")
    with pytest.raises(SigmaError):
        event_matches_rule(rule_re, {"Image": "cmd.exe"})


def test_result_serializes_to_json():
    result = compare_rules(RULE_V1, RULE_V2_ADDED_VALUE)
    assert '"relation": "expands"' in result.to_json()


def test_list_of_maps_expands():
    rule_a = """
title: A
logsource:
    product: windows
detection:
    selection:
        - Image: cmd.exe
          User: SYSTEM
        - Image: powershell.exe
    condition: selection
"""
    rule_b = """
title: B
logsource:
    product: windows
detection:
    selection:
        - Image: cmd.exe
          User: SYSTEM
        - Image: powershell.exe
        - Image: pwsh.exe
    condition: selection
"""
    result = compare_rules(rule_a, rule_b)
    assert result.relation == Relation.EXPANDS
    assert result.distinguishing_event == {"Image": "pwsh.exe"}


def test_unsatisfiable_rule_scope():
    rule_unsat = """
title: Contradiction
logsource:
    product: windows
detection:
    a:
        Image: cmd.exe
    b:
        Image: powershell.exe
    condition: a and b
"""
    assert compare_rules(rule_unsat, rule_unsat).relation == Relation.EQUIVALENT
    # an empty scope is a subset of anything: adding a value expands it
    rule_sat = rule_unsat.replace("condition: a and b", "condition: a or b")
    result = compare_rules(rule_unsat, rule_sat)
    assert result.relation == Relation.EXPANDS
    assert result.distinguishing_event is not None
