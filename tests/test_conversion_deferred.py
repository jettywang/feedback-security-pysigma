import pytest
from sigma.conversion.state import ConversionState
from sigma.conversion.deferred import DeferredTextQueryExpression
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionOR
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.collection import SigmaCollection
from sigma.backends.test import TextQueryTestBackend


### Base Tests ###
@pytest.fixture
def conversion_state():
    return ConversionState()


class DeferredTestExpression(DeferredTextQueryExpression):
    template = '{field}{op}"{value}"'
    operators = {
        True: "!=",
        False: "=",
    }
    default_field = "_"


@pytest.fixture
def deferred_expression(conversion_state):
    return DeferredTestExpression(conversion_state, "field", "value")


@pytest.fixture
def deferred_expression_nofield(conversion_state):
    return DeferredTestExpression(conversion_state, None, "value")


def test_deferred_expression(deferred_expression):
    assert deferred_expression.finalize_expression() == 'field="value"'


def test_deferred_expression_negation(deferred_expression):
    assert deferred_expression.negate().finalize_expression() == 'field!="value"'


def test_deferred_default_field(deferred_expression_nofield):
    assert deferred_expression_nofield.finalize_expression() == '_="value"'


### Conversion Tests ###
class DeferredTextQueryTestBackend(TextQueryTestBackend):
    re_expression = "{regex}"
    re_escape = tuple()

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DeferredTestExpression:
        return DeferredTestExpression(
            state, cond.field, super().convert_condition_field_eq_val_re(cond, state)
        )


@pytest.fixture
def test_backend():
    return DeferredTextQueryTestBackend()


def test_deferred_conversion_and(test_backend: TextQueryTestBackend):
    assert test_backend.convert(SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """)) == ['fieldB="foo" and fieldC="bar" | mappedA="foo.*bar"']


def test_deferred_conversion_or(test_backend: TextQueryTestBackend):
    # "sel1 or sel2 or sel3" contains a deferred regex on the left branch. Appending it to
    # the main query would AND it with the OR of the plain branches, so it must be rejected
    # instead of silently narrowing or broadening the rule.
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="OR condition"):
        test_backend.convert(SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA|re: foo.*bar
                sel2:
                    fieldB: foo
                sel3:
                    fieldC: bar
                condition: sel1 or sel2 or sel3
        """))


def test_deferred_conversion_multiple_cond(test_backend: TextQueryTestBackend):
    assert test_backend.convert(SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA|re: foo.*bar
                sel2:
                    fieldB|re: foo.*
                sel3:
                    fieldC|re: .*bar
                condition:
                    - sel1
                    - sel2
                    - sel3
        """)) == ['* | mappedA="foo.*bar"', '* | fieldB="foo.*"', '* | fieldC=".*bar"']


def test_deferred_conversion_not(test_backend: TextQueryTestBackend):
    assert test_backend.convert(SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldB: foo
                    fieldC: bar
                sel2:
                    fieldA|re: foo.*bar
                condition: sel1 and not sel2
        """)) == ['fieldB="foo" and fieldC="bar" | mappedA!="foo.*bar"']


def test_deferred_only_conversion(test_backend: TextQueryTestBackend):
    assert test_backend.convert(SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                condition: sel
        """)) == ['* | mappedA="foo.*bar"']


def test_deferred_conversion_correlation_rule_references(test_backend: TextQueryTestBackend):
    assert (
        test_backend.convert(SigmaCollection.from_yaml("""
title: Referenced Rule with Deferred
name: rule_with_deferred
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA|re: foo.*bar
        fieldB: normalvalue
    condition: sel
---
title: Correlation Rule
status: test
correlation:
    type: event_count
    rules:
        - rule_with_deferred
    group-by:
        - fieldC
    timespan: 5m
    condition:
        gte: 10
        """))
        == ["""fieldB="normalvalue" | mappedA="foo.*bar"
| aggregate window=5min count() as event_count by fieldC
| where event_count >= 10"""]
    )


def deferred_rule(detection: str) -> SigmaCollection:
    return SigmaCollection.from_yaml(f"""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
{detection}
""")


def test_deferred_conversion_not_and_mixed_unsupported(test_backend: TextQueryTestBackend):
    # not (fieldB="foo" and fieldA ~ regex) can't be expressed as main query plus an appended
    # regex filter: only the fieldB part would be negated and the regex would become required.
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="Negation"):
        test_backend.convert(deferred_rule("""
    sel:
        fieldC: bar
    filter:
        fieldB: foo
        fieldA|re: foo.*bar
    condition: sel and not filter"""))


def test_deferred_conversion_not_and_mixed_collect_errors():
    backend = DeferredTextQueryTestBackend(collect_errors=True)
    assert backend.convert(deferred_rule("""
    sel:
        fieldC: bar
    filter:
        fieldB: foo
        fieldA|re: foo.*bar
    condition: sel and not filter""")) == []
    assert len(backend.errors) == 1
    assert isinstance(backend.errors[0][1], SigmaFeatureNotSupportedByBackendError)


@pytest.mark.parametrize(
    "condition",
    [
        "not (sel1 and sel2)",
        "not (sel1 or sel2)",
        "sel3 and not (sel1 or sel3)",
    ],
)
def test_deferred_conversion_not_compound_unsupported(
    test_backend: TextQueryTestBackend, condition
):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        test_backend.convert(deferred_rule(f"""
    sel1:
        fieldA|re: foo.*bar
    sel2:
        fieldB|re: foo.*
    sel3:
        fieldC: bar
    condition: {condition}"""))


@pytest.mark.parametrize(
    "detection,expected",
    [
        (
            """
    sel:
        fieldA|re: foo.*bar
        fieldB|re: foo.*
    condition: sel""",
            '* | mappedA="foo.*bar" | fieldB="foo.*"',
        ),
        (
            """
    sel1:
        fieldA|re: foo.*bar
    sel2:
        fieldB|re: foo.*
    condition: sel1 and sel2""",
            '* | mappedA="foo.*bar" | fieldB="foo.*"',
        ),
        (
            """
    sel1:
        fieldA|re: foo.*bar
    sel2:
        fieldB|re: foo.*
    condition: not sel1 and not sel2""",
            '* | mappedA!="foo.*bar" | fieldB!="foo.*"',
        ),
        (
            """
    sel1:
        fieldA|re: foo.*bar
    sel2:
        fieldB|re: foo.*
    sel3:
        fieldC: bar
    condition: sel3 and (sel1 and sel2)""",
            'fieldC="bar" | mappedA="foo.*bar" | fieldB="foo.*"',
        ),
    ],
    ids=["one_selection", "and", "not_and_not", "nested_and"],
)
def test_deferred_conversion_all_deferred_and(
    test_backend: TextQueryTestBackend, detection, expected
):
    assert test_backend.convert(deferred_rule(detection)) == [expected]


def test_deferred_conversion_double_negation(test_backend: TextQueryTestBackend):
    assert test_backend.convert(deferred_rule("""
    sel1:
        fieldA|re: foo.*bar
    sel2:
        fieldC: bar
    condition: sel2 and not (not sel1)""")) == ['fieldC="bar" | mappedA="foo.*bar"']


class EnablerDeferredTextQueryTestBackend(DeferredTextQueryTestBackend):
    """
    Converts regular expressions below an OR into a query term that is enabled by a deferred
    expression (like the rex/eval handling of the Splunk backend). Such deferred expressions are
    not operands of the condition and must not prevent negation.
    """

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ):
        if cond.parent_condition_chain_contains(ConditionOR):
            DeferredTestExpression(state, "enable", cond.field)
            return f'{cond.field}Condition="true"'
        return super().convert_condition_field_eq_val_re(cond, state)


def test_deferred_conversion_not_with_enabler_deferred():
    assert (
        EnablerDeferredTextQueryTestBackend().convert(deferred_rule("""
    sel1:
        fieldA|re: foo.*bar
    sel2:
        fieldB: foo
    sel3:
        fieldC: bar
    condition: sel3 and not (sel1 or sel2)"""))
        == ['fieldC="bar" and not (mappedACondition="true" or fieldB="foo") | enable="mappedA"']
    )


def deferred_or_rule(condition: str) -> SigmaCollection:
    return SigmaCollection.from_yaml(f"""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel1:
        fieldA|re: foo.*bar
    sel2:
        fieldB|re: foo.*
    sel3:
        fieldC: bar
    sel_list:
        fieldA|re:
            - foo.*
            - bar.*
    condition: {condition}
""")


@pytest.mark.parametrize(
    "condition",
    [
        "sel_list",
        "sel1 or sel2",
        "sel1 or sel_list",
        "sel3 and (sel1 or sel2)",
        "sel3 or (sel1 and sel2)",
        "sel1 or (sel2 or sel_list)",
    ],
)
def test_deferred_conversion_all_deferred_or_unsupported(
    test_backend: TextQueryTestBackend, condition
):
    # An OR containing deferred expressions on any branch can't be expressed by appending
    # them to the main query (this would AND them). The rule must not be dropped silently.
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="OR condition"):
        test_backend.convert(deferred_or_rule(condition))


def test_deferred_conversion_all_deferred_or_collect_errors():
    backend = DeferredTextQueryTestBackend(collect_errors=True)
    assert backend.convert(deferred_or_rule("sel1 or sel2")) == []
    assert len(backend.errors) == 1
    assert isinstance(backend.errors[0][1], SigmaFeatureNotSupportedByBackendError)


class DroppingDeferredTextQueryTestBackend(DeferredTextQueryTestBackend):
    """Converts fieldC conditions into nothing."""

    def convert_condition_field_eq_val_str(self, cond, state):
        if cond.field == "fieldC":
            return None
        return super().convert_condition_field_eq_val_str(cond, state)


def test_deferred_conversion_or_single_deferred_with_empty():
    assert DroppingDeferredTextQueryTestBackend().convert(deferred_or_rule("sel1 or sel3")) == [
        '* | mappedA="foo.*bar"'
    ]


class ScopeDeferredTextQueryTestBackend(DeferredTextQueryTestBackend):
    """Minimal text backend used to probe deferred scope semantics.

    In-expressions are disabled so that every leaf keeps its own condition node and the
    converted text can be evaluated as a small boolean expression. Deferred filters are
    appended after the main query with ``deferred_start`` and are interpreted by the test
    helper below as AND-linked filters on the events selected by the main query.
    """

    convert_or_as_in = False
    convert_and_as_in = False


scope_backend = ScopeDeferredTextQueryTestBackend()


def _scope_rule(condition: str):
    return SigmaCollection.from_yaml(f"""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
    a:
        fieldB: foo
    b:
        fieldC: bar
    r:
        fieldA|re: foo.*bar
    s:
        fieldD|re: bar.*baz
    condition: {condition}
""").rules[0]


def _leaf_value(cond, event):
    from sigma.types import SigmaRegularExpression, SigmaString

    actual = event.get(cond.field, "")
    if isinstance(cond.value, SigmaString):
        return str(actual).lower() == str(cond.value).lower()
    if isinstance(cond.value, SigmaRegularExpression):
        import re

        return re.search(str(cond.value.regexp), str(actual)) is not None
    raise TypeError(type(cond.value))


def _evaluate_condition_tree(cond, event):
    """Evaluate the original Sigma condition tree directly on a dict event."""
    from sigma.conditions import (
        ConditionAND,
        ConditionFieldEqualsValueExpression,
        ConditionNOT,
        ConditionOR,
        ConditionValueExpression,
    )

    if isinstance(cond, ConditionAND):
        return all(_evaluate_condition_tree(arg, event) for arg in cond.args)
    if isinstance(cond, ConditionOR):
        return any(_evaluate_condition_tree(arg, event) for arg in cond.args)
    if isinstance(cond, ConditionNOT):
        return not _evaluate_condition_tree(cond.args[0], event)
    if isinstance(cond, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
        return _leaf_value(cond, event)
    raise TypeError(type(cond))


def _evaluate_query(query: str, event):
    """Evaluate the test backend query: main expression, then AND-linked deferred filters."""
    import re

    main, *filters = (part.strip() for part in query.split("|"))
    tokens = re.findall(r'\(|\)|!=|=|\band\b|\bor\b|\bnot\b|"[^"]*"|\w+', main)
    position = 0

    def peek():
        return tokens[position] if position < len(tokens) else None

    def take():
        nonlocal position
        token = tokens[position]
        position += 1
        return token

    def atom():
        if peek() == "(":
            take()
            value = expr_or()
            assert take() == ")"
            return value
        if peek() == "not":
            take()
            return not atom()
        field, operator, value = take(), take(), take().strip('"')
        actual = str(event.get(field, ""))
        return actual.lower() == value.lower() if operator == "=" else actual != value

    def expr_and():
        value = atom()
        while peek() == "and":
            take()
            value = atom() and value
        return value

    def expr_or():
        value = expr_and()
        while peek() == "or":
            take()
            value = expr_and() or value
        return value

    result = True if main == "*" else expr_or()
    assert position == len(tokens), tokens
    for deferred_filter in filters:
        match = re.fullmatch(r"([A-Za-z0-9_]+)(!?=)([\"'])(.*?)([\"'])$", deferred_filter)
        assert match, deferred_filter
        field, operator, _, value, _ = match.groups()
        matched = re.search(value, str(event.get(field, ""))) is not None
        result = result and (not matched if operator == "!=" else matched)
    return result


SCOPE_EVENTS = [
    {"fieldB": "foo", "fieldC": "bar", "fieldA": "fooXXbar", "fieldD": "barXXbaz"},
    {"fieldB": "foo", "fieldC": "nope", "fieldA": "nope", "fieldD": "nope"},
    {"fieldB": "nope", "fieldC": "bar", "fieldA": "nope", "fieldD": "nope"},
    {"fieldB": "nope", "fieldC": "nope", "fieldA": "fooXXbar", "fieldD": "barXXbaz"},
    {"fieldB": "nope", "fieldC": "nope", "fieldA": "fooXXbar", "fieldD": "nope"},
    {"fieldB": "foo", "fieldC": "bar", "fieldA": "nope", "fieldD": "barXXbaz"},
    {"fieldB": "foo", "fieldC": "nope", "fieldA": "fooXXbar", "fieldD": "nope"},
    {"fieldB": "nope", "fieldC": "bar", "fieldA": "fooXXbar", "fieldD": "barXXbaz"},
]


def test_deferred_conversion_or_scope_rejected_with_distinguishing_event():
    # "a or r" is true for the event {"fieldB": "nope", "fieldA": "fooXXbar"}. The backend used
    # to emit 'fieldB="foo" | mappedA="foo.*bar"', which only matches events satisfying
    # fieldB="foo" *and* the deferred regex. Event 4 is selected by the expected query but
    # missed by the buggy promotion of the deferred branch to a global filter.
    rule = _scope_rule("a or r")
    condition = rule.detection.parsed_condition[0].parsed
    event = SCOPE_EVENTS[4]
    assert _evaluate_condition_tree(condition, event) is True
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="OR condition"):
        scope_backend.convert_rule(rule)


def test_deferred_conversion_and_scope_is_equivalent():
    # Plain AND with a deferred operand is expressible: deferred filters AND-link to the
    # whole main query, which is exactly the meaning of the Sigma condition.
    condition = "a and r"
    rule = _scope_rule(condition)
    query = scope_backend.convert_rule(rule)[0]
    expected = [
        _evaluate_condition_tree(rule.detection.parsed_condition[0].parsed, event)
        for event in SCOPE_EVENTS
    ]
    actual = [_evaluate_query(query, event) for event in SCOPE_EVENTS]
    assert query == 'fieldB="foo" | mappedA="foo.*bar"'
    assert expected == actual


def test_deferred_conversion_and_and_not_scope_is_equivalent():
    # "a and not r" negates the deferred leaf itself, so the deferred operator is flipped
    # and the filter remains equivalent to the original condition.
    rule = _scope_rule("a and not r")
    query = scope_backend.convert_rule(rule)[0]
    expected = [
        _evaluate_condition_tree(rule.detection.parsed_condition[0].parsed, event)
        for event in SCOPE_EVENTS
    ]
    actual = [_evaluate_query(query, event) for event in SCOPE_EVENTS]
    assert query == 'fieldB="foo" | mappedA!="foo.*bar"'
    assert expected == actual


def test_deferred_conversion_not_inside_and_scope_rejected():
    # "not (a or r)" can't be expressed as a global deferred filter. The backend rejects it
    # rather than emitting a query where the negation only covers the plain branch.
    rule = _scope_rule("not (a or r)")
    event = SCOPE_EVENTS[1]  # fieldB="foo", fieldA="nope": original condition is false
    assert _evaluate_condition_tree(rule.detection.parsed_condition[0].parsed, event) is False
    # The negated OR is rejected by the OR guard before the NOT-specific guard triggers.
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="deferred query expressions"):
        scope_backend.convert_rule(rule)


def test_deferred_conversion_multi_rule_scope_isolation():
    # Consecutive compilation must keep deferred state per rule. The supported AND rule is
    # emitted, the OR rule is rejected, and a later rule must not see leftover filters from
    # the previous rule.
    collection = SigmaCollection.from_yaml("""
title: Supported AND
status: test
logsource:
    category: test_category
    product: test_product
detection:
    a:
        fieldB: foo
    r:
        fieldA|re: foo.*bar
    condition: a and r
---
title: Unsupported OR
status: test
logsource:
    category: test_category
    product: test_product
detection:
    a:
        fieldB: foo
    r:
        fieldA|re: foo.*bar
    condition: a or r
---
title: Later plain rule
status: test
logsource:
    category: test_category
    product: test_product
detection:
    a:
        fieldB: foo
    condition: a
---
title: Later AND rule
status: test
logsource:
    category: test_category
    product: test_product
detection:
    a:
        fieldB: foo
    r:
        fieldA|re: foo.*bar
    condition: r
""")
    backend = ScopeDeferredTextQueryTestBackend(collect_errors=True)
    queries = backend.convert(collection)
    assert queries == [
        'fieldB="foo" | mappedA="foo.*bar"',
        'fieldB="foo"',
        '* | mappedA="foo.*bar"',
    ]
    assert [type(error) for _, error in backend.errors] == [SigmaFeatureNotSupportedByBackendError]
