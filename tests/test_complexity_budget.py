"""
Tests for the conversion-wide complexity budget.

The budget protects a rule compilation service that accepts external Sigma content from
small inputs that expand into huge query trees. It covers the three expansion mechanisms:

* condition selectors (``1 of selection_*``),
* expanding value modifiers (``base64offset`` / ``windash``),
* one-to-many field name mappings.

The tests assert that combinatorial growth is rejected early with precise attribution while
large but linear rules still convert, and that a rejected conversion leaves no reusable
partial state behind.
"""

import pytest

from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.conversion.budget import (
    STAGE_CONDITION_SELECTOR,
    STAGE_FIELD_MAPPING,
    STAGE_MODIFIER_EXPANSION,
    ComplexityBudget,
    current_budget,
)
from sigma.exceptions import SigmaComplexityBudgetExceededError
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation


@pytest.fixture
def empty_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline()


def make_selector_rule(count: int) -> str:
    """A rule whose single selector fans out into ``count`` detection identifiers."""
    selections = "\n".join(
        f"    selection_{i}:\n        field_{i}: value_{i}" for i in range(count)
    )
    return f"""
title: selector bomb
logsource:
    category: test
detection:
{selections}
    condition: 1 of selection_*
"""


def make_linear_value_rule(count: int) -> str:
    """A rule with ``count`` plain values in one detection item (purely linear growth)."""
    values = ", ".join(f'"value_{i}"' for i in range(count))
    return f"""
title: linear value rule
logsource:
    category: test
detection:
    selection:
        field: [{values}]
    condition: selection
"""


# ---------------------------------------------------------------------------
# Condition selector expansion
# ---------------------------------------------------------------------------


def test_selector_expansion_rejected_when_over_budget(empty_pipeline: ProcessingPipeline):
    backend = TextQueryTestBackend(empty_pipeline, complexity_budget=8)
    rule = make_selector_rule(12)

    with pytest.raises(SigmaComplexityBudgetExceededError) as exc_info:
        backend.convert(SigmaCollection.from_yaml(rule))

    error = exc_info.value
    assert error.stage == STAGE_CONDITION_SELECTOR
    assert error.rule == "selector bomb"
    assert error.limit == 8
    assert error.consumed == 12


def test_selector_within_budget_converts(empty_pipeline: ProcessingPipeline):
    backend = TextQueryTestBackend(empty_pipeline, complexity_budget=100)
    rule = make_selector_rule(12)

    queries = backend.convert(SigmaCollection.from_yaml(rule))

    assert len(queries) == 1
    assert "field_0" in queries[0]
    assert "field_11" in queries[0]


# ---------------------------------------------------------------------------
# Linear rules are treated differently from combinatorial expansion
# ---------------------------------------------------------------------------


def test_large_linear_value_rule_still_converts_under_tiny_budget(
    empty_pipeline: ProcessingPipeline,
):
    # 200 plain values produce a long but linear query and consume no expansion budget.
    backend = TextQueryTestBackend(empty_pipeline, complexity_budget=1)
    rule = make_linear_value_rule(200)

    queries = backend.convert(SigmaCollection.from_yaml(rule))

    assert queries[0].count("value_") == 200


def make_matched_pair() -> tuple[str, str]:
    """
    Two rules of *identical* byte length with identical detection blocks.

    The combinatorial one expresses the join with a ``1 of selection_*`` selector whose single
    condition token fans out into one branch per detection at conversion time; the linear one
    spells out the same join as an explicit ``or`` chain, which is already fully present in the
    YAML and therefore performs no selector expansion. A YAML comment pads the shorter selector
    condition line so the serialized inputs are exactly the same size.
    """
    count = 12
    detections = "".join(
        f"    selection_{i}:\n        field_{i}: value_{i}\n" for i in range(count)
    )
    selector_cond = "1 of selection_*"
    explicit_cond = " or ".join(f"selection_{i}" for i in range(count))
    gap = len(explicit_cond) - len(selector_cond)
    combinatorial = (
        "title: matched-pair\nlogsource:\n  category: test\ndetection:\n"
        + detections
        + "    condition: "
        + selector_cond
        + "  # "
        + ("x" * (gap - 4))
        + "\n"
    )
    linear = (
        "title: matched-pair\nlogsource:\n  category: test\ndetection:\n"
        + detections
        + "    condition: "
        + explicit_cond
        + "\n"
    )
    assert len(combinatorial) == len(linear)
    return combinatorial, linear


def test_linear_and_combinatorial_inputs_have_close_byte_length_but_diverge(
    empty_pipeline: ProcessingPipeline,
):
    """The headline guarantee: identical byte size, different expansion fate."""
    combinatorial, linear = make_matched_pair()
    assert len(combinatorial) == len(linear)

    combo_backend = TextQueryTestBackend(empty_pipeline, complexity_budget=8)
    linear_backend = TextQueryTestBackend(ProcessingPipeline(), complexity_budget=8)

    with pytest.raises(SigmaComplexityBudgetExceededError) as exc_info:
        combo_backend.convert(SigmaCollection.from_yaml(combinatorial))
    assert exc_info.value.stage == STAGE_CONDITION_SELECTOR

    # The explicit, already-materialized condition compiles under the same budget.
    assert linear_backend.convert(SigmaCollection.from_yaml(linear))


# ---------------------------------------------------------------------------
# Modifier expansion (happens while the rule YAML is parsed)
# ---------------------------------------------------------------------------


def make_modifier_rule(count: int) -> str:
    values = ", ".join(f'"val{i}xy"' for i in range(count))
    return f"""
title: modifier bomb
logsource:
    category: test
detection:
    selection:
        field|base64offset: [{values}]
    condition: selection
"""


def make_linear_modifier_rule(count: int, target_length: int | None = None) -> str:
    values = ", ".join(f'"val{i}xy"' for i in range(count))
    rule = f"""
title: modifier bomb
logsource:
    category: test
detection:
    selection:
        field|base64: [{values}]
    condition: selection
"""
    if target_length is not None:
        # Pad with a YAML comment so the linear sample is byte-identical in length to the
        # expanding one. The "  # " prefix is 4 chars; the rest is made of x's. The trailing
        # comment does not change the parsed rule.
        gap = target_length - len(rule)
        assert gap >= 4
        rule = rule.replace(
            f"field|base64: [{values}]\n",
            f"field|base64: [{values}]  # {'x' * (gap - 4)}\n",
        )
    return rule


def test_expanding_modifier_rejected_during_parsing(empty_pipeline: ProcessingPipeline):
    backend = TextQueryTestBackend(empty_pipeline, complexity_budget=5)
    # Each base64offset value grows one value into three candidates (+2); five values => 10.
    rule = make_modifier_rule(5)

    with pytest.raises(SigmaComplexityBudgetExceededError) as exc_info:
        backend.convert_untrusted_yaml(rule)

    error = exc_info.value
    assert error.stage == STAGE_MODIFIER_EXPANSION
    assert error.rule == "modifier bomb"
    assert error.consumed > error.limit


def test_windash_modifier_rejected_early_from_tiny_input(
    empty_pipeline: ProcessingPipeline,
):
    # A single short value with three dash positions fans out into well over a hundred
    # candidates via the windash modifier, so a small byte input is rejected at parse time.
    rule = """
title: windash bomb
logsource:
    category: test
detection:
    selection:
        field|windash: '-a -b -c'
    condition: selection
"""
    backend = TextQueryTestBackend(empty_pipeline, complexity_budget=50)

    with pytest.raises(SigmaComplexityBudgetExceededError) as exc_info:
        backend.convert_untrusted_yaml(rule)

    error = exc_info.value
    assert error.stage == STAGE_MODIFIER_EXPANSION
    assert error.consumed > 100


def test_linear_one_to_one_modifier_under_tiny_budget(empty_pipeline: ProcessingPipeline):
    # base64 maps one value onto exactly one value, so it consumes no expansion budget.
    backend = TextQueryTestBackend(empty_pipeline, complexity_budget=1)
    rule = make_linear_modifier_rule(50)

    queries = backend.convert_untrusted_yaml(rule)

    assert len(queries) == 1


def test_similar_sized_modifier_inputs_diverge(empty_pipeline: ProcessingPipeline):
    expanding = make_modifier_rule(5)
    linear = make_linear_modifier_rule(5, target_length=len(expanding))
    assert len(expanding) == len(linear)

    with pytest.raises(SigmaComplexityBudgetExceededError) as exc_info:
        TextQueryTestBackend(
            ProcessingPipeline(), complexity_budget=5
        ).convert_untrusted_yaml(expanding)
    assert exc_info.value.stage == STAGE_MODIFIER_EXPANSION

    assert TextQueryTestBackend(
        ProcessingPipeline(), complexity_budget=5
    ).convert_untrusted_yaml(linear)


# ---------------------------------------------------------------------------
# One-to-many field mapping
# ---------------------------------------------------------------------------


def fanout_pipeline(targets: int) -> ProcessingPipeline:
    # fieldZ is not touched by the test backend's built-in dummy pipeline.
    return ProcessingPipeline(
        [
            ProcessingItem(
                identifier="fanout-item",
                transformation=FieldMappingTransformation(
                    {"fieldZ": [f"mapped_{i}" for i in range(targets)]}
                ),
            )
        ]
    )


FANOUT_RULE = """
title: field fanout
logsource:
    category: test
detection:
    selection:
        fieldZ: bomb
    condition: selection
"""


def test_field_fanout_rejected_with_processing_item_attribution():
    backend = TextQueryTestBackend(fanout_pipeline(12), complexity_budget=8)

    with pytest.raises(SigmaComplexityBudgetExceededError) as exc_info:
        backend.convert(SigmaCollection.from_yaml(FANOUT_RULE))

    error = exc_info.value
    assert error.stage == STAGE_FIELD_MAPPING
    assert error.processing_item == "fanout-item"
    assert error.rule == "field fanout"
    assert error.consumed == 11


def test_one_to_one_field_mapping_is_linear_and_passes():
    pipeline = ProcessingPipeline(
        [
            ProcessingItem(
                identifier="rename-item",
                transformation=FieldMappingTransformation({"fieldZ": "mapped_z"}),
            )
        ]
    )
    backend = TextQueryTestBackend(pipeline, complexity_budget=1)

    assert backend.convert(SigmaCollection.from_yaml(FANOUT_RULE)) == ['mapped_z="bomb"']


# ---------------------------------------------------------------------------
# Shared accumulation across pipeline + conversion, and diagnostics
# ---------------------------------------------------------------------------


def test_budget_accumulates_across_processing_items(empty_pipeline: ProcessingPipeline):
    pipeline = ProcessingPipeline(
        [
            ProcessingItem(
                identifier="first-fanout",
                transformation=FieldMappingTransformation(
                    {"fieldZ": ["z0", "z1", "z2", "z3"]}
                ),
            ),
        ]
    )
    backend = TextQueryTestBackend(pipeline, complexity_budget=2)

    with pytest.raises(SigmaComplexityBudgetExceededError) as exc_info:
        backend.convert(SigmaCollection.from_yaml(FANOUT_RULE))

    # 4 targets => 3 extra candidates, crossing the limit of 2 during the first item.
    assert exc_info.value.consumed == 3
    assert exc_info.value.processing_item == "first-fanout"


def test_budget_is_shared_across_rules_in_one_collection(
    empty_pipeline: ProcessingPipeline,
):
    first = make_selector_rule(5).replace("selector bomb", "first rule")
    second = make_selector_rule(5).replace("selector bomb", "second rule")
    collection = SigmaCollection.from_yaml(first + "---\n" + second)

    backend = TextQueryTestBackend(empty_pipeline, complexity_budget=7)

    with pytest.raises(SigmaComplexityBudgetExceededError) as exc_info:
        backend.convert(collection)

    # First rule costs 5, the second adds another 5 and crosses the shared limit of 7.
    error = exc_info.value
    assert error.consumed == 10
    assert error.rule == "second rule"
    assert error.stage == STAGE_CONDITION_SELECTOR


def test_budget_charges_record_stage_and_location(empty_pipeline: ProcessingPipeline):
    budget = ComplexityBudget(limit=100)
    budget.begin_rule_label("diagnostic rule")
    budget.begin_processing_item("item-1")
    budget.charge(4, STAGE_FIELD_MAPPING)
    budget.end_processing_item()
    budget.charge(2, STAGE_CONDITION_SELECTOR)

    assert budget.consumed == 6
    assert [(c.amount, c.stage, c.rule, c.processing_item) for c in budget.charges] == [
        (4, STAGE_FIELD_MAPPING, "diagnostic rule", "item-1"),
        (2, STAGE_CONDITION_SELECTOR, "diagnostic rule", None),
    ]


# ---------------------------------------------------------------------------
# Failure hygiene: no reusable partial state, backend stays usable
# ---------------------------------------------------------------------------


def test_convert_rule_entry_point_enforces_budget_standalone(
    empty_pipeline: ProcessingPipeline,
):
    # The single-rule entry point must activate the budget even when convert() was not used.
    backend = TextQueryTestBackend(empty_pipeline, complexity_budget=5)
    rule = SigmaCollection.from_yaml(make_selector_rule(12)).rules[0]

    with pytest.raises(SigmaComplexityBudgetExceededError):
        backend.convert_rule(rule)

    assert backend._active_budget is None
    assert current_budget() is None


def test_no_budget_leftover_is_active_after_failure(empty_pipeline: ProcessingPipeline):
    backend = TextQueryTestBackend(empty_pipeline, complexity_budget=8)

    with pytest.raises(SigmaComplexityBudgetExceededError):
        backend.convert(SigmaCollection.from_yaml(make_selector_rule(12)))

    assert backend._active_budget is None
    assert current_budget() is None


def test_pipeline_tracking_state_is_reset_after_failure():
    pipeline = fanout_pipeline(12)
    backend = TextQueryTestBackend(pipeline, complexity_budget=8)
    backend.init_processing_pipeline()

    with pytest.raises(SigmaComplexityBudgetExceededError):
        backend.convert(SigmaCollection.from_yaml(FANOUT_RULE))

    combined = backend.last_processing_pipeline
    assert combined.applied == []
    assert combined.applied_ids == set()
    assert dict(combined.field_mappings) == {}
    assert combined.state == {}


def test_backend_converts_a_small_rule_identically_after_rejection():
    """Same backend instance, post-failure conversion must match a fresh instance."""
    pipeline = fanout_pipeline(12)
    backend = TextQueryTestBackend(pipeline, complexity_budget=8)

    with pytest.raises(SigmaComplexityBudgetExceededError):
        backend.convert(SigmaCollection.from_yaml(FANOUT_RULE))

    small_rule = """
title: small rule
logsource:
    category: test
detection:
    selection:
        otherField: ok
    condition: selection
"""
    fresh_backend = TextQueryTestBackend(
        ProcessingPipeline(
            [
                ProcessingItem(
                    identifier="fanout-item",
                    transformation=FieldMappingTransformation(
                        {"fieldZ": [f"mapped_{i}" for i in range(12)]}
                    ),
                )
            ]
        ),
        complexity_budget=8,
    )

    reused_result = backend.convert(SigmaCollection.from_yaml(small_rule))
    fresh_result = fresh_backend.convert(SigmaCollection.from_yaml(small_rule))

    assert reused_result == fresh_result == ['otherField="ok"']


def test_caller_rule_object_is_not_mutated_when_budget_trips(
    empty_pipeline: ProcessingPipeline,
):
    backend = TextQueryTestBackend(fanout_pipeline(12), complexity_budget=8)
    rule = SigmaCollection.from_yaml(FANOUT_RULE).rules[0]
    before = rule.to_dict()

    with pytest.raises(SigmaComplexityBudgetExceededError):
        backend.convert(SigmaCollection.from_yaml(FANOUT_RULE))

    # The rule held by the caller is a different object than the private copy the backend
    # transformed, so its serialized form must be untouched.
    assert rule.to_dict() == before


# ---------------------------------------------------------------------------
# Disabled budget keeps the legacy unbounded behavior
# ---------------------------------------------------------------------------


def test_disabled_budget_keeps_legacy_behavior(empty_pipeline: ProcessingPipeline):
    backend = TextQueryTestBackend(empty_pipeline)
    assert backend.complexity_budget is None

    queries = backend.convert(
        SigmaCollection.from_yaml(make_selector_rule(50))
    )
    assert len(queries) == 1


def test_explicit_constructor_budget_overrides_class_default():
    class BudgetedBackend(TextQueryTestBackend):
        complexity_budget = 100

    backend = BudgetedBackend(ProcessingPipeline(), complexity_budget=5)
    assert backend.complexity_budget == 5

    default_backend = BudgetedBackend(ProcessingPipeline())
    assert default_backend.complexity_budget == 100
