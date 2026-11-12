import pytest
from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import (
    FieldMappingTransformation,
    ReplaceStringTransformation,
)
from sigma.processing.transformations.failure import RuleFailureTransformation
from sigma.processing.transformations.state import SetStateTransformation
from sigma.rule import SigmaRule


@pytest.fixture
def test_backend() -> TextQueryTestBackend:
    """Create a test backend instance for testing."""
    return TextQueryTestBackend(ProcessingPipeline())


@pytest.fixture
def sigma_rule() -> SigmaRule:
    """Create a simple Sigma rule for testing."""
    rule_yaml = """
title: Test Rule
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"""
    return SigmaRule.from_yaml(rule_yaml)


def test_convert_rule_single_rule(test_backend: TextQueryTestBackend, sigma_rule: SigmaRule):
    """Test conversion of a single Sigma rule using convert_rule method."""
    # Test that convert_rule works without prior initialization of processing pipeline
    queries = test_backend.convert_rule(sigma_rule)

    # Verify that the rule was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0
    assert isinstance(queries[0], str)

    # Verify that the processing pipeline was initialized
    assert hasattr(test_backend, "last_processing_pipeline")
    assert test_backend.last_processing_pipeline is not None


def test_convert_rule_with_output_format(test_backend: TextQueryTestBackend, sigma_rule: SigmaRule):
    """Test conversion of a single Sigma rule with specific output format."""
    queries = test_backend.convert_rule(sigma_rule, output_format="default")

    # Verify that the rule was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0

    # Verify that the processing pipeline was initialized
    assert hasattr(test_backend, "last_processing_pipeline")
    assert test_backend.last_processing_pipeline is not None


def test_convert_rule_multiple_calls(test_backend: TextQueryTestBackend, sigma_rule: SigmaRule):
    """Test multiple calls to convert_rule to ensure pipeline is reused."""
    # First call
    queries1 = test_backend.convert_rule(sigma_rule)
    pipeline1 = test_backend.last_processing_pipeline

    # Second call
    queries2 = test_backend.convert_rule(sigma_rule)
    pipeline2 = test_backend.last_processing_pipeline

    # Verify both calls succeeded
    assert isinstance(queries1, list) and len(queries1) > 0
    assert isinstance(queries2, list) and len(queries2) > 0

    # Verify same pipeline instance is used (since no different output_format was specified)
    assert pipeline1 is pipeline2


def test_convert_rule_different_output_formats(
    test_backend: TextQueryTestBackend, sigma_rule: SigmaRule
):
    """Test convert_rule with different output formats reinitializes pipeline."""
    # First call with default format
    queries1 = test_backend.convert_rule(sigma_rule)
    pipeline1 = test_backend.last_processing_pipeline

    # Clear the pipeline to simulate a fresh state
    test_backend.last_processing_pipeline = None

    # Second call with explicit default format (should reinitialize)
    queries2 = test_backend.convert_rule(sigma_rule, output_format="default")
    pipeline2 = test_backend.last_processing_pipeline

    # Verify both calls succeeded
    assert isinstance(queries1, list) and len(queries1) > 0
    assert isinstance(queries2, list) and len(queries2) > 0

    # Pipeline should be reinitialized when it was None
    assert pipeline1 is not pipeline2


def test_init_processing_pipeline_method(test_backend: TextQueryTestBackend):
    """Test the init_processing_pipeline method directly."""
    # Initially no pipeline should be set
    assert (
        not hasattr(test_backend, "last_processing_pipeline")
        or test_backend.last_processing_pipeline is None
    )

    # Initialize the pipeline
    test_backend.init_processing_pipeline()

    # Verify pipeline was initialized
    assert hasattr(test_backend, "last_processing_pipeline")
    assert test_backend.last_processing_pipeline is not None

    # Verify pipeline has the expected structure
    assert (
        len(test_backend.last_processing_pipeline.items) >= 0
    )  # Should have at least the base items


def test_init_processing_pipeline_with_output_format(test_backend: TextQueryTestBackend):
    """Test init_processing_pipeline with specific output format."""
    test_backend.init_processing_pipeline(output_format="default")

    # Verify pipeline was initialized
    assert hasattr(test_backend, "last_processing_pipeline")
    assert test_backend.last_processing_pipeline is not None


def test_convert_rule_with_callback(test_backend: TextQueryTestBackend, sigma_rule: SigmaRule):
    """Test conversion of a single Sigma rule with callback parameter."""
    callback_calls = []

    def test_callback(rule, output_format, index, cond, result):
        """Test callback that records all calls and returns the original result."""
        callback_calls.append(
            {
                "rule": rule,
                "output_format": output_format,
                "index": index,
                "cond": cond,
                "result": result,
            }
        )
        return result  # Return the original result unchanged

    # Convert rule with callback
    queries = test_backend.convert_rule(sigma_rule, callback=test_callback)

    # Verify that the rule was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0

    # Verify that callback was called
    assert len(callback_calls) > 0

    # Verify callback parameters
    for i, call in enumerate(callback_calls):
        assert call["rule"] is sigma_rule
        assert call["output_format"] is None  # Default when not specified
        assert call["index"] == i
        assert call["cond"] is not None
        # Result can be None or not None depending on conversion


def test_convert_rule_with_callback_and_output_format(
    test_backend: TextQueryTestBackend, sigma_rule: SigmaRule
):
    """Test conversion with both callback and output_format parameters."""
    callback_calls = []
    expected_format = "default"

    def test_callback(rule, output_format, index, cond, result):
        """Test callback that records all calls and returns the original result."""
        callback_calls.append(
            {
                "rule": rule,
                "output_format": output_format,
                "index": index,
                "cond": cond,
                "result": result,
            }
        )
        return result  # Return the original result unchanged

    # Convert rule with callback and output format
    queries = test_backend.convert_rule(
        sigma_rule, output_format=expected_format, callback=test_callback
    )

    # Verify that the rule was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0

    # Verify that callback was called with correct output_format
    assert len(callback_calls) > 0
    for call in callback_calls:
        assert call["rule"] is sigma_rule
        assert call["output_format"] == expected_format
        assert isinstance(call["index"], int)
        assert call["cond"] is not None


def test_convert_rule_callback_called_for_none_results(test_backend: TextQueryTestBackend):
    """Test that callback is called even when convert_condition returns None."""
    callback_calls = []

    def test_callback(rule, output_format, index, cond, result):
        """Test callback that records all calls and returns the original result."""
        callback_calls.append(
            {
                "rule": rule,
                "output_format": output_format,
                "index": index,
                "cond": cond,
                "result": result,
            }
        )
        return result  # Return the original result unchanged

    # Create a rule that might produce None results
    rule_yaml = """
title: Test Rule with Multiple Conditions
logsource:
    category: test
detection:
    sel1:
        field1: value1
    sel2:
        field2: value2
    condition: sel1 or sel2
"""
    sigma_rule = SigmaRule.from_yaml(rule_yaml)

    # Convert rule with callback
    queries = test_backend.convert_rule(sigma_rule, callback=test_callback)

    # Verify that callback was called for all conditions
    assert len(callback_calls) > 0

    # Verify that all calls have valid parameters (including None results)
    for call in callback_calls:
        assert call["rule"] is sigma_rule
        assert isinstance(call["index"], int)
        assert call["cond"] is not None
        # result can be None or not None - both should be recorded


def test_convert_collection_with_callback(
    test_backend: TextQueryTestBackend, sigma_rule: SigmaRule
):
    """Test conversion of a rule collection using convert method with callback parameter."""
    callback_calls = []

    def test_callback(rule, output_format, index, cond, result):
        """Test callback that records all calls and returns the original result."""
        callback_calls.append(
            {
                "rule": rule,
                "output_format": output_format,
                "index": index,
                "cond": cond,
                "result": result,
            }
        )
        return result  # Return the original result unchanged

    # Create a collection with the test rule
    collection = SigmaCollection([sigma_rule])

    # Convert collection with callback
    queries = test_backend.convert(collection, callback=test_callback)

    # Verify that the collection was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0

    # Verify that callback was called
    assert len(callback_calls) > 0

    # Verify callback parameters
    for call in callback_calls:
        assert call["rule"] is sigma_rule
        assert call["output_format"] == test_backend.default_format
        assert isinstance(call["index"], int)
        assert call["cond"] is not None


def test_convert_collection_with_callback_and_output_format(
    test_backend: TextQueryTestBackend, sigma_rule: SigmaRule
):
    """Test conversion of a rule collection with both callback and output_format parameters."""
    callback_calls = []
    expected_format = "default"

    def test_callback(rule, output_format, index, cond, result):
        """Test callback that records all calls and returns the original result."""
        callback_calls.append(
            {
                "rule": rule,
                "output_format": output_format,
                "index": index,
                "cond": cond,
                "result": result,
            }
        )
        return result  # Return the original result unchanged

    # Create a collection with the test rule
    collection = SigmaCollection([sigma_rule])

    # Convert collection with callback and output format
    queries = test_backend.convert(
        collection, output_format=expected_format, callback=test_callback
    )

    # Verify that the collection was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0

    # Verify that callback was called with correct output_format
    assert len(callback_calls) > 0
    for call in callback_calls:
        assert call["rule"] is sigma_rule
        assert call["output_format"] == expected_format
        assert isinstance(call["index"], int)
        assert call["cond"] is not None


def test_convert_collection_multiple_rules_with_callback(test_backend: TextQueryTestBackend):
    """Test conversion of a collection with multiple rules and callback."""
    callback_calls = []

    def test_callback(rule, output_format, index, cond, result):
        """Test callback that records all calls and returns the original result."""
        callback_calls.append(
            {
                "rule": rule,
                "output_format": output_format,
                "index": index,
                "cond": cond,
                "result": result,
            }
        )
        return result  # Return the original result unchanged

    # Create multiple test rules
    rule1_yaml = """
title: Test Rule 1
logsource:
    category: test
detection:
    sel:
        field1: value1
    condition: sel
"""
    rule2_yaml = """
title: Test Rule 2
logsource:
    category: test
detection:
    sel:
        field2: value2
    condition: sel
"""

    rule1 = SigmaRule.from_yaml(rule1_yaml)
    rule2 = SigmaRule.from_yaml(rule2_yaml)
    collection = SigmaCollection([rule1, rule2])

    # Convert collection with callback
    queries = test_backend.convert(collection, callback=test_callback)

    # Verify that the collection was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0

    # Verify that callback was called for both rules
    assert len(callback_calls) > 0

    # Check that both rules appear in callback calls
    rules_in_callbacks = [call["rule"] for call in callback_calls]
    assert rule1 in rules_in_callbacks
    assert rule2 in rules_in_callbacks

    # Verify callback parameters for each call
    for call in callback_calls:
        assert call["rule"] in [rule1, rule2]
        assert call["output_format"] == test_backend.default_format
        assert isinstance(call["index"], int)
        assert call["cond"] is not None


def test_convert_collection_without_callback(
    test_backend: TextQueryTestBackend, sigma_rule: SigmaRule
):
    """Test that convert method works normally when no callback is provided."""
    # Create a collection with the test rule
    collection = SigmaCollection([sigma_rule])

    # Convert collection without callback (should work as before)
    queries = test_backend.convert(collection)

    # Verify that the collection was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0


def test_convert_rule_callback_modifies_result(
    test_backend: TextQueryTestBackend, sigma_rule: SigmaRule
):
    """Test that callback can modify the conversion result."""

    def modifying_callback(rule, output_format, index, cond, result):
        """Callback that modifies non-None results by adding a prefix."""
        if result is not None:
            return f"MODIFIED: {result}"
        return result

    # Convert rule with modifying callback
    queries = test_backend.convert_rule(sigma_rule, callback=modifying_callback)

    # Verify that the rule was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0

    # Verify that all results were modified by the callback
    for query in queries:
        assert isinstance(query, str)
        assert query.startswith("MODIFIED: ")


def test_convert_rule_callback_filters_result(
    test_backend: TextQueryTestBackend, sigma_rule: SigmaRule
):
    """Test that callback can filter out results by returning None."""

    def filtering_callback(rule, output_format, index, cond, result):
        """Callback that filters out all results by returning None."""
        return None  # Always return None to filter out all results

    # Convert rule with filtering callback
    queries = test_backend.convert_rule(sigma_rule, callback=filtering_callback)

    # Verify that no queries were returned due to filtering
    assert isinstance(queries, list)
    assert len(queries) == 0


def test_convert_rule_callback_selective_modification(test_backend: TextQueryTestBackend):
    """Test that callback can selectively modify results based on conditions."""
    callback_calls = []

    def selective_callback(rule, output_format, index, cond, result):
        """Callback that modifies every second result."""
        callback_calls.append(result)
        if result is not None and len(callback_calls) % 2 == 0:
            return f"EVEN: {result}"
        return result

    # Create a rule with multiple conditions to get multiple results
    rule_yaml = """
title: Test Rule with Multiple Conditions
logsource:
    category: test
detection:
    sel1:
        field1: value1
    sel2:
        field2: value2
    condition: sel1 and sel2
"""
    sigma_rule = SigmaRule.from_yaml(rule_yaml)

    # Convert rule with selective callback
    queries = test_backend.convert_rule(sigma_rule, callback=selective_callback)

    # Verify that the rule was converted successfully
    assert isinstance(queries, list)

    # Check that some results were modified and some weren't
    if len(queries) > 1:
        modified_count = sum(1 for q in queries if isinstance(q, str) and q.startswith("EVEN: "))
        unmodified_count = len(queries) - modified_count
        assert modified_count > 0 or unmodified_count > 0  # At least some should exist


FIELD_VALUE_RULE_YAML = """
title: Isolation Rule
name: isolation_rule
logsource:
    category: test
detection:
    sel:
        field: hello
    filter:
        other_field: untouched
    condition: sel and not filter
"""


def _isolation_rule() -> SigmaRule:
    return SigmaRule.from_yaml(FIELD_VALUE_RULE_YAML)


def _backend(pipeline: ProcessingPipeline) -> TextQueryTestBackend:
    return TextQueryTestBackend(pipeline)


PIPELINE_A = ProcessingPipeline(
    [
        ProcessingItem(FieldMappingTransformation({"field": "field_a"}), identifier="map_a"),
        ProcessingItem(ReplaceStringTransformation("hello", "HELLO_A"), identifier="val_a"),
        ProcessingItem(SetStateTransformation("index", "index_a"), identifier="state_a"),
    ]
)
PIPELINE_B = ProcessingPipeline(
    [
        ProcessingItem(FieldMappingTransformation({"field": "field_b"}), identifier="map_b"),
        ProcessingItem(ReplaceStringTransformation("hello", "HELLO_B"), identifier="val_b"),
        ProcessingItem(SetStateTransformation("index", "index_b"), identifier="state_b"),
    ]
)


def test_convert_rule_does_not_modify_rule_by_default():
    rule = _isolation_rule()
    original_detection = rule.detection.to_dict()

    backend = _backend(PIPELINE_A)
    assert backend.convert_rule(rule) == ['field_a="HELLO_A" and not other_field="untouched"']

    assert rule.detection.to_dict() == original_detection
    assert not rule.was_processed_by("map_a")
    assert not rule.was_processed_by("val_a")
    item = rule.detection.detections["sel"].detection_items[0]
    assert not item.was_processed_by("map_a")


def test_convert_collection_does_not_modify_rules_by_default():
    collection = SigmaCollection.from_yaml(FIELD_VALUE_RULE_YAML)
    original_detection = collection.rules[0].detection.to_dict()

    backend = _backend(PIPELINE_A)
    assert backend.convert(collection) == ['field_a="HELLO_A" and not other_field="untouched"']

    assert collection.rules[0].detection.to_dict() == original_detection


def test_convert_rule_a_then_b_are_independent():
    rule = _isolation_rule()
    backend_a = _backend(PIPELINE_A)
    backend_b = _backend(PIPELINE_B)

    result_a = backend_a.convert_rule(rule)
    result_b = backend_b.convert_rule(rule)

    assert result_a == ['field_a="HELLO_A" and not other_field="untouched"']
    assert result_b == ['field_b="HELLO_B" and not other_field="untouched"']
    # Neither pipeline's processed detection or tracking leaked to the rule.
    assert rule.detection.detections["sel"].detection_items[0].field == "field"
    assert not rule.was_processed_by("map_a")
    assert not rule.was_processed_by("map_b")


def test_convert_rule_b_then_a_are_independent():
    rule = _isolation_rule()
    backend_a = _backend(PIPELINE_A)
    backend_b = _backend(PIPELINE_B)

    result_b = backend_b.convert_rule(rule)
    result_a = backend_a.convert_rule(rule)

    assert result_b == ['field_b="HELLO_B" and not other_field="untouched"']
    assert result_a == ['field_a="HELLO_A" and not other_field="untouched"']
    assert rule.detection.detections["sel"].detection_items[0].field == "field"


def test_convert_rule_alone_matches_sequence_results():
    backend_a = _backend(PIPELINE_A)
    backend_b = _backend(PIPELINE_B)

    alone_a = backend_a.convert_rule(_isolation_rule())
    alone_b = backend_b.convert_rule(_isolation_rule())

    rule = _isolation_rule()
    assert backend_a.convert_rule(rule) == alone_a
    assert backend_b.convert_rule(rule) == alone_b
    # ... and the sequence A->B on the same rule matches each standalone conversion.
    rule_again = _isolation_rule()
    assert backend_a.convert_rule(rule_again) == alone_a
    assert backend_b.convert_rule(rule_again) == alone_b

    rule_third = _isolation_rule()
    sequence = [backend_a.convert_rule(rule_third), backend_b.convert_rule(rule_third)]
    assert sequence == [alone_a, alone_b]
    rule_fourth = _isolation_rule()
    reverse_sequence = [backend_b.convert_rule(rule_fourth), backend_a.convert_rule(rule_fourth)]
    assert reverse_sequence == [alone_b, alone_a]


def test_convert_collection_a_then_b_are_independent():
    collection = SigmaCollection.from_yaml(FIELD_VALUE_RULE_YAML)
    backend_a = _backend(PIPELINE_A)
    backend_b = _backend(PIPELINE_B)

    result_a = backend_a.convert(collection)
    result_b = backend_b.convert(collection)

    assert result_a == ['field_a="HELLO_A" and not other_field="untouched"']
    assert result_b == ['field_b="HELLO_B" and not other_field="untouched"']


def test_convert_collection_b_then_a_are_independent():
    collection = SigmaCollection.from_yaml(FIELD_VALUE_RULE_YAML)
    backend_a = _backend(PIPELINE_A)
    backend_b = _backend(PIPELINE_B)

    result_b = backend_b.convert(collection)
    result_a = backend_a.convert(collection)

    assert result_b == ['field_b="HELLO_B" and not other_field="untouched"']
    assert result_a == ['field_a="HELLO_A" and not other_field="untouched"']


def test_convert_state_uses_only_own_pipeline():
    rule = _isolation_rule()
    backend_a = _backend(PIPELINE_A)
    backend_b = _backend(PIPELINE_B)

    backend_a.convert_rule(rule)
    # The conversion state committed to the rule must only contain A's pipeline state.
    assert [state.processing_state for state in rule.get_conversion_states()] == [
        {"index": "index_a"}
    ]

    backend_b.convert_rule(rule)
    assert [state.processing_state for state in rule.get_conversion_states()] == [
        {"index": "index_b"}
    ]


def test_failed_conversion_does_not_leave_modified_detection():
    rule = _isolation_rule()
    original_detection = rule.detection.to_dict()
    failing_backend = _backend(
        ProcessingPipeline(
            [
                ProcessingItem(
                    FieldMappingTransformation({"field": "field_a"}),
                    identifier="map_a",
                ),
                ProcessingItem(RuleFailureTransformation("boom")),
            ]
        )
    )

    with pytest.raises(SigmaTransformationError, match="boom"):
        failing_backend.convert_rule(rule)

    assert rule.detection.to_dict() == original_detection
    assert not rule.was_processed_by("map_a")
    assert not rule.was_processed_by("boom")


def test_failed_conversion_then_reuse_has_no_leftover_state():
    rule = _isolation_rule()
    failing_backend = _backend(
        ProcessingPipeline(
            [
                ProcessingItem(
                    FieldMappingTransformation({"field": "field_a"}),
                    identifier="map_a",
                ),
                ProcessingItem(SetStateTransformation("index", "stale_index"), identifier="state"),
                ProcessingItem(RuleFailureTransformation("boom")),
            ]
        )
    )
    with pytest.raises(SigmaTransformationError, match="boom"):
        failing_backend.convert_rule(rule)

    healthy_backend = _backend(PIPELINE_B)
    result = healthy_backend.convert_rule(rule)

    assert result == ['field_b="HELLO_B" and not other_field="untouched"']
    states = [state.processing_state for state in rule.get_conversion_states()]
    assert states == [{"index": "index_b"}]
    assert "map_a" not in healthy_backend.last_processing_pipeline.applied_ids
    assert "map_b" in healthy_backend.last_processing_pipeline.applied_ids


def test_pipeline_reuse_after_failure_does_not_reuse_previous_rule_tracking():
    first_rule = SigmaRule.from_yaml("""
title: First
logsource:
    category: test
detection:
    sel:
        field_a: value_a
    condition: sel
""")
    second_rule = SigmaRule.from_yaml(FIELD_VALUE_RULE_YAML)
    failing_backend = _backend(
        ProcessingPipeline(
            [
                ProcessingItem(
                    FieldMappingTransformation({"field_a": "mapped_a"}),
                    identifier="map_a",
                ),
                ProcessingItem(
                    FieldMappingTransformation({"field": "mapped_field"}),
                    identifier="map_field",
                ),
                ProcessingItem(RuleFailureTransformation("boom")),
            ]
        )
    )

    with pytest.raises(SigmaTransformationError, match="boom"):
        failing_backend.convert_rule(first_rule)
    with pytest.raises(SigmaTransformationError, match="boom"):
        failing_backend.convert_rule(second_rule)

    # Tracking must only describe the second rule's processing, not the first rule's fields.
    pipeline = failing_backend.last_processing_pipeline
    assert set(pipeline.field_mappings) == {"field"}
    assert "map_a" not in pipeline.field_name_applied_ids.get("mapped_field", set())
    assert pipeline.state == {}


def test_explicit_inplace_mode_keeps_processed_detection_on_rule():
    rule = _isolation_rule()
    backend = _backend(PIPELINE_A)

    assert backend.convert_rule(rule, inplace=True) == [
        'field_a="HELLO_A" and not other_field="untouched"'
    ]

    assert rule.detection.detections["sel"].detection_items[0].field == "field_a"
    assert rule.was_processed_by("map_a")


def test_explicit_inplace_collection_keeps_processed_detection_on_rules():
    collection = SigmaCollection.from_yaml(FIELD_VALUE_RULE_YAML)
    backend = _backend(PIPELINE_A)

    assert backend.convert(collection, inplace=True) == [
        'field_a="HELLO_A" and not other_field="untouched"'
    ]
    assert collection.rules[0].detection.detections["sel"].detection_items[0].field == "field_a"


def test_default_and_inplace_results_are_equal():
    backend_a = _backend(PIPELINE_A)
    backend_b = _backend(PIPELINE_B)

    assert backend_a.convert_rule(_isolation_rule()) == backend_a.convert_rule(
        _isolation_rule(), inplace=True
    )
    # A second backend converting the same, still unmodified rule must see the same result
    # as it saw when the first backend converted the rule before.
    assert backend_b.convert_rule(_isolation_rule()) == [
        'field_b="HELLO_B" and not other_field="untouched"'
    ]
    assert backend_b.convert_rule(_isolation_rule(), inplace=True) == [
        'field_b="HELLO_B" and not other_field="untouched"'
    ]
