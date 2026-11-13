"""
Semantic tests for chains of value-encoding modifiers (wide, base64offset) followed by contains.

The tests deliberately evaluate encoded sample logs against an expression-only backend instead of
comparing generated query strings. A small reference oracle, implemented with the standard library
only, decides which byte layouts are expected to match, so that the assertions describe the
intended behaviour rather than a snapshot of what the implementation happens to emit.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import ClassVar

import pytest

from sigma.collection import SigmaCollection
from sigma.conversion.base import TextQueryBackend
from sigma.exceptions import SigmaModifiedError, SigmaValueError
from sigma.matching import Event, EventLogSource, SigmaMatcher
from sigma.modifiers import SigmaBase64OffsetModifier, SigmaContainsModifier, SigmaWideModifier
from sigma.rule import SigmaDetectionItem, SigmaRule
from sigma.types import SigmaCasedString, SigmaExpansion, SigmaString, SpecialChars


### Reference oracle ###
# The helpers below implement the semantics of wide and base64offset independently from the code
# under test, using only the standard library. They answer "which encoded sample must the
# generated rule hit" and "which neighbouring payload must it reject".


def wide_bytes(text: str) -> bytes:
    """Reference implementation of the wide modifier: UTF-16LE encoding of the whole text."""
    return text.encode("utf-16le")


def base64_offset_windows(data: bytes) -> list[str]:
    """
    Reference implementation of base64offset.

    For each of the three possible byte alignments of ``data`` inside an encoded blob, return the
    Base64 substring made only of characters whose six bits all originate from ``data`` itself.
    Such a substring is present in every Base64 encoding that contains ``data`` at this alignment,
    independent of the bytes before and after it. Characters at either boundary can mix in bits of
    those unknown bytes and are therefore excluded. If no full Base64 character is covered at one
    alignment, no fragment is defined for it.
    """
    windows: list[str] = []
    for alignment in range(3):
        start_bit = 8 * alignment
        end_bit = 8 * (alignment + len(data))
        first = -(-start_bit // 6)  # first Base64 char starting inside data
        last = end_bit // 6  # first char starting beyond data
        covered = [
            character
            for character in range(first, last)
            if 6 * character >= start_bit and 6 * character + 6 <= end_bit
        ]
        if not covered:
            continue
        padding = (-(alignment + len(data))) % 3  # only influences chars after `last`
        canonical = base64.b64encode(
            b"\x00" * alignment + data + b"\x00" * padding
        ).decode()
        windows.append(canonical[covered[0] : covered[-1] + 1])
    return windows


def base64_encoded_sample(data: bytes, alignment: int, suffix: bytes = b"") -> str:
    """Base64 blob that embeds ``data`` at the given alignment of a longer log attribute."""
    assert 0 <= alignment < 3
    prefix = bytes([0x00]) * alignment
    return base64.b64encode(prefix + data + suffix).decode()


def covered_byte_indices(data_length: int, alignment: int) -> list[int]:
    """
    Byte indices of the target whose bits are fully inside the base64offset fragment emitted for
    the given alignment. The fragment spans only the characters whose six bits all originate from
    the target; a change in a byte outside this set may fall into boundary or padding bits and can
    legitimately remain undetected.
    """
    start_bit = 8 * alignment
    end_bit = 8 * (alignment + data_length)
    first_character = -(-start_bit // 6)
    last_character = end_bit // 6
    covered_characters = [
        character
        for character in range(first_character, last_character)
        if 6 * character >= start_bit and 6 * character + 6 <= end_bit
    ]
    if not covered_characters:
        return []
    fragment_start_bit = 6 * covered_characters[0]
    fragment_end_bit = 6 * (covered_characters[-1] + 1)
    return [
        index
        for index in range(data_length)
        if fragment_start_bit <= 8 * (alignment + index)
        and 8 * (alignment + index) + 8 <= fragment_end_bit
    ]


def _contains(text: str, literal: str, *, cased: bool) -> bool:
    if cased:
        return literal in text
    return literal.casefold() in text.casefold()


### Expression-only test backend ###
# The backend supports exactly the expressions these tests need: equality, substring containment
# and the boolean combinators. No real SIEM is involved and no query text is compared.


@dataclass(frozen=True)
class ContainsExpression:
    field: str
    literal: str
    cased: bool = False


@dataclass(frozen=True)
class EqualsExpression:
    field: str
    literal: str
    cased: bool = False


@dataclass(frozen=True)
class OrExpression:
    args: tuple


@dataclass(frozen=True)
class AndExpression:
    args: tuple


@dataclass(frozen=True)
class NotExpression:
    arg: object


class ExpressionOnlyBackend(TextQueryBackend):
    """Minimal backend that turns the condition tree into comparable expression objects."""

    name: ClassVar[str] = "Expression-only encoded modifier test backend"
    formats: ClassVar[dict[str, str]] = {"default": "expression objects"}

    group_expression: ClassVar[str | None] = "({expr})"
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"
    eq_token: ClassVar[str] = "="
    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str | None] = "*"
    wildcard_single: ClassVar[str | None] = "?"

    # Only the contains operator is required. Equality is handled explicitly below.
    contains_expression: ClassVar[str | None] = "contains"
    startswith_expression: ClassVar[str | None] = None
    endswith_expression: ClassVar[str | None] = None
    wildcard_match_expression: ClassVar[str | None] = None

    convert_or_as_in: ClassVar[bool] = False
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = True

    def convert_condition_or(self, cond, state):
        return OrExpression(tuple(self.convert_condition(arg, state) for arg in cond.args))

    def convert_condition_and(self, cond, state):
        return AndExpression(tuple(self.convert_condition(arg, state) for arg in cond.args))

    def convert_condition_not(self, cond, state):
        return NotExpression(self.convert_condition(cond.args[0], state))

    def convert_condition_group(self, cond, state):
        return self.convert_condition(cond, state)

    def convert_condition_field_eq_val_str(self, cond, state):
        return self._string_expression(cond, cased=isinstance(cond.value, SigmaCasedString))

    def convert_condition_field_eq_val_str_case_sensitive(self, cond, state):
        return self._string_expression(cond, cased=True)

    def _string_expression(self, cond, *, cased: bool):
        value = cond.value
        if value.startswith(SpecialChars.WILDCARD_MULTI) and value.endswith(
            SpecialChars.WILDCARD_MULTI
        ):
            inner = value[1:-1]
            if not inner.contains_special():
                return ContainsExpression(cond.field, str(inner), cased)
        if not value.contains_special():
            return EqualsExpression(cond.field, str(value), cased)
        raise NotImplementedError(
            f"Expression-only backend can't express the string value {value!r}"
        )

    def finish_query(self, rule, query, state):
        return query

    def finalize_query_default(self, rule, query, index, state):
        return query


def build_expression(key: str, value: str) -> object:
    """Parse a detection item with the given modifier chain and convert it to an expression."""
    rule = SigmaRule.from_dict(
        {
            "title": "encoded modifier semantics",
            "name": "encoded_modifier_semantics",
            "status": "test",
            "logsource": {"category": "test", "product": "test"},
            "detection": {"selection": {key: value}, "condition": "selection"},
        }
    )
    queries = ExpressionOnlyBackend().convert(SigmaCollection([rule]))
    if len(queries) != 1:
        raise AssertionError(f"expected exactly one expression, got {queries!r}")
    return queries[0]


def field_literals(expression: object, field: str = "field") -> list[str]:
    """All literals the expression looks for in the given field."""
    if isinstance(expression, (ContainsExpression, EqualsExpression)):
        return [expression.literal] if expression.field == field else []
    if isinstance(expression, (OrExpression, AndExpression)):
        literals: list[str] = []
        for argument in expression.args:
            literals.extend(field_literals(argument, field))
        return literals
    if isinstance(expression, NotExpression):
        return field_literals(expression.arg, field)
    raise TypeError(f"unexpected expression {expression!r}")


def evaluate(expression: object, attribute_value: str) -> bool:
    """Evaluate the expression against one log attribute."""
    if isinstance(expression, ContainsExpression):
        return _contains(attribute_value, expression.literal, cased=expression.cased)
    if isinstance(expression, EqualsExpression):
        if expression.cased:
            return attribute_value == expression.literal
        return attribute_value.casefold() == expression.literal.casefold()
    if isinstance(expression, OrExpression):
        return any(evaluate(argument, attribute_value) for argument in expression.args)
    if isinstance(expression, AndExpression):
        return all(evaluate(argument, attribute_value) for argument in expression.args)
    if isinstance(expression, NotExpression):
        return not evaluate(expression.arg, attribute_value)
    raise TypeError(f"unexpected expression {expression!r}")


def hits(expression: object, sample: str) -> bool:
    return evaluate(expression, sample)


def rule_detection(key: str, value: str) -> SigmaCollection:
    return SigmaCollection.from_yaml(
        f"""
title: encoded modifier semantics
name: encoded_modifier_semantics
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        "{key}": "{value}"
    condition: selection
"""
    )


def matcher_hits(collection: SigmaCollection, attribute_value: str) -> int:
    """End-to-end check with the built-in matcher that consumes the produced expressions."""
    with SigmaMatcher(collection) as matcher:
        event = Event(
            timestamp=datetime.now(timezone.utc),
            logsource=EventLogSource(category="test", product="test"),
            data={"field": attribute_value},
        )
        return len(matcher.match(event))


### Modifier order keeps its meaning ###
def test_wide_then_base64offset_carries_both_encodings():
    expression = build_expression("field|wide|base64offset|contains", "cmd.exe")
    expected = base64_offset_windows(wide_bytes("cmd.exe"))
    assert field_literals(expression) == expected


def test_base64offset_before_wide_encodes_base64_text_not_original_bytes():
    # wide after base64offset must widen the already encoded characters: this is a different
    # payload from wide|base64offset and must not be conflated with it.
    expression = build_expression("field|base64offset|contains|wide", "cmd.exe")
    expected = [
        window.encode("utf-16le").decode("utf-8")
        for window in base64_offset_windows(b"cmd.exe")
    ]
    assert field_literals(expression) == expected


def test_base64offset_before_wide_neither_matches_widened_original_nor_plain_base64():
    # The literal is the widened Base64 text, so neither a wide UTF-16LE log nor a plain
    # Base64 log of the original string is a match.
    expression = build_expression("field|base64offset|contains|wide", "cmd.exe")
    for alignment in range(3):
        assert not hits(expression, base64_encoded_sample("cmd.exe".encode(), alignment))
        assert not hits(expression, base64_encoded_sample(wide_bytes("cmd.exe"), alignment))
    for window in base64_offset_windows("cmd.exe".encode()):
        assert not hits(expression, window)


def test_identically_ordered_contains_modifiers_are_stable():
    # contains is idempotent: repeating it doesn't change the expression.
    first = build_expression("field|contains", "cmd.exe")
    repeated = build_expression("field|contains|contains", "cmd.exe")
    assert first == repeated


def test_base64offset_before_contains_is_the_supported_order():
    # base64offset must run on the bare value; contains then wraps each fragment.
    expression = build_expression("field|base64offset|contains", "cmd.exe")
    assert field_literals(expression) == base64_offset_windows(b"cmd.exe")


def test_contains_before_base64offset_fails_explicitly():
    # The reverse order feeds wildcard-bearing values into the encoder. It must fail loudly
    # instead of encoding the wildcards or silently dropping contains.
    with pytest.raises(SigmaValueError, match="wildcards is not allowed"):
        SigmaDetectionItem.from_mapping("field|contains|base64offset", "cmd.exe")


def test_base64offset_after_contains_inside_encoded_chain_fails_explicitly():
    with pytest.raises(SigmaValueError, match="wildcards is not allowed"):
        SigmaDetectionItem.from_mapping("field|base64offset|contains|base64offset", "cmd.exe")


@pytest.mark.parametrize(
    "key",
    [
        "field|contains|startswith",
        "field|startswith|contains",
        "field|contains|endswith",
        "field|endswith|contains",
        "field|startswith|endswith",
        "field|endswith|startswith",
        "field|wide|contains|startswith",
    ],
)
def test_conflicting_anchoring_modifier_orders_fail_explicitly(key):
    # Two substring anchors cannot both hold. Such a chain must be rejected instead of silently
    # dropping or overwriting one of them and widening the match.
    with pytest.raises(SigmaModifiedError, match="must not be combined"):
        SigmaDetectionItem.from_mapping(key, "cmd.exe")


### Alignment offsets ###
@pytest.mark.parametrize(
    "key,encode",
    [
        ("field|base64offset|contains", lambda text: text.encode()),
        ("field|wide|base64offset|contains", wide_bytes),
    ],
)
@pytest.mark.parametrize("alignment", [0, 1, 2])
def test_each_of_the_three_alignments_is_hit(key, encode, alignment):
    expression = build_expression(key, "cmd.exe")
    data = encode("cmd.exe")
    sample = base64_encoded_sample(data, alignment)
    assert hits(expression, sample), (alignment, sample)
    # Every alignment of this long target has at least one invariant fragment.
    windows = base64_offset_windows(data)
    assert len(windows) == 3
    assert windows[alignment] in sample  # reference invariant


@pytest.mark.parametrize(
    "key,encode",
    [
        ("field|base64offset|contains", lambda text: text.encode()),
        ("field|wide|base64offset|contains", wide_bytes),
    ],
)
@pytest.mark.parametrize(
    "suffix",
    [b"", b"\x00\x00", b"\x01\x02\x03", b"trailing log text"],
)
def test_alignment_hits_are_independent_of_surrounding_bytes(key, encode, suffix):
    expression = build_expression(key, "cmd.exe")
    data = encode("cmd.exe")
    for alignment in range(3):
        sample = base64_encoded_sample(data, alignment, suffix)
        assert hits(expression, sample), (alignment, suffix)
        # A different payload must not be accepted merely because the surrounding log text
        # changed. "dmc.exe" differs in the first two bytes, which every alignment covers.
        other = base64_encoded_sample(encode("dmc.exe"), alignment, suffix)
        assert not hits(expression, other), (alignment, suffix)


### Non-ASCII text ###
@pytest.mark.parametrize("text", ["cmd.éxe", "日本語", "café.exe"])
def test_non_ascii_utf8_text_at_every_alignment(text):
    expression = build_expression("field|base64offset|contains", text)
    data = text.encode("utf-8")
    windows = base64_offset_windows(data)
    assert len(windows) == 3  # long enough targets always have a fragment for every alignment
    for alignment in range(3):
        sample = base64_encoded_sample(data, alignment)
        assert windows[alignment] in sample  # reference invariant
        assert hits(expression, sample)


def test_non_ascii_windows_are_rejected_before_encoding():
    with pytest.raises(SigmaValueError, match="ascii strings"):
        SigmaDetectionItem.from_mapping("field|wide|base64offset|contains", "cmd.éxe")


def test_non_ascii_wide_payload_is_hit_when_wide_is_not_applied_to_the_literal():
    # The utf16 modifier accepts arbitrary Unicode; only `wide` is ASCII-limited.
    expression = build_expression("field|utf16|base64offset|contains", "cmd.exe")
    data = b"\xff\xfe" + "cmd.exe".encode("utf-16le")
    for alignment in range(3):
        sample = base64_encoded_sample(data, alignment)
        assert hits(expression, sample), (alignment, sample)


def test_utf16_modifier_is_limited_to_characters_that_round_trip_through_utf8():
    with pytest.raises(SigmaValueError, match="valid Unicode strings"):
        SigmaDetectionItem.from_mapping("field|utf16|base64offset|contains", "cmd.éxe")


### Trailing padding ###
@pytest.mark.parametrize("text", ["abcd", "abcdefg", "cmd.exe"])
def test_padding_at_the_end_of_the_target_is_handled(text):
    # Values whose last Base64 block ends in '=' padding must still match when the padded
    # target ends the log attribute.
    expression = build_expression("field|base64offset|contains", text)
    data = text.encode()
    for alignment in range(3):
        sample = base64_encoded_sample(data, alignment)
        assert hits(expression, sample)


@pytest.mark.parametrize("text", ["a", "ab", ""])
def test_short_or_empty_values_do_not_become_match_all(text):
    # A too-short value has no full Base64 character at some alignments. Those alignments must
    # contribute nothing instead of an empty fragment that matches every log attribute.
    if text == "":  # no fragment at all, so nothing can match
        with pytest.raises(SigmaValueError, match="empty string"):
            build_expression("field|base64offset|contains", text)
        return
    expression = build_expression("field|base64offset|contains", text)
    assert "" not in field_literals(expression)
    assert field_literals(expression) == base64_offset_windows(text.encode())
    # A Base64 log that shares no fragment with "a" or "ab" is rejected...
    assert not hits(expression, "QWxs")  # Base64 of "all"
    # ...but a single Base64 character is a prefix of many unrelated blobs, e.g. "Y" of
    # "YWFh" ("aaa"). This is the inherent short-value trade-off of base64offset.
    for window in base64_offset_windows(text.encode()):
        assert hits(expression, window)


def test_empty_target_is_rejected_instead_of_matching_everything():
    with pytest.raises(SigmaValueError, match="empty string"):
        SigmaDetectionItem.from_mapping("field|base64offset|contains", "")


def test_wide_target_padding_is_handled():
    expression = build_expression("field|wide|base64offset|contains", "abc")
    data = wide_bytes("abc")
    for alignment in range(3):
        assert hits(expression, base64_encoded_sample(data, alignment))


### Reference counterexample: a string snapshot would miss this ###
def test_snapshot_of_generated_query_and_live_semantics_counterexample():
    """
    A snapshot of the generated *query string* is blind to what the expression actually accepts.

    The values below deliberately show two different failure modes:

    1. ``base64offset|contains`` with a one-character value: the old implementation emitted an
       empty fragment for alignment 1, which ``contains`` wrapped into the single wildcard ``*``.
       The generated query still looked like a normal list of ``contains`` terms, a string
       snapshot could perfectly well approve it, yet that wildcard-only literal matched *every*
       log line. The corrected implementation omits that alignment, so a sample that contains
       neither of the two remaining one-character fragments ("Y" and "h") is rejected.

    2. ``wide|base64offset|contains`` against the same fragments: ``plain`` and ``widened`` are two
       different byte layouts, and a log encoded in the "wrong" layout must not match. A snapshot
       of either query only contains the fragment characters, not the byte layout they encode.

    The live evaluation below distinguishes all of these, which a query snapshot cannot.
    """
    expression = build_expression("field|base64offset|contains", "a")
    literals = field_literals(expression)
    assert literals == base64_offset_windows(b"a")  # no empty fragment survived
    assert literals == ["Y", "h"]
    # A one-character Base64 fragment is a common prefix, e.g. "Y" of "YWFh" is acceptable, but
    # "QQ==" ("@") contains neither fragment and must be rejected outright. The legacy empty
    # fragment, by contrast, was `"" in every attribute` and matched even this unrelated sample.
    assert not hits(expression, "QQ==")
    assert not hits(expression, "")  # an empty attribute matched the legacy match-all fragment

    # A snapshot cannot see the byte layout. The plain and widened chains accept different blobs.
    plain = build_expression("field|base64offset|contains", "cmd.exe")
    widened = build_expression("field|wide|base64offset|contains", "cmd.exe")
    plain_data = "cmd.exe".encode()
    wide_data = wide_bytes("cmd.exe")
    for alignment in range(3):
        plain_sample = base64_encoded_sample(plain_data, alignment)
        wide_sample = base64_encoded_sample(wide_data, alignment)
        assert hits(plain, plain_sample)
        assert hits(widened, wide_sample)
        if base64_offset_windows(wide_data)[alignment] not in plain_sample:
            assert not hits(plain, wide_sample)
        if base64_offset_windows(plain_data)[alignment] not in wide_sample:
            assert not hits(widened, plain_sample)

    # The case-sensitivity marker is another aspect invisible to a snapshot: ``cased`` before an
    # encoder used to produce exactly the same query as without it. It is rejected explicitly now,
    # so a snapshot can no longer hide that the flag was silently dropped.
    with pytest.raises(SigmaModifiedError, match="cased"):
        build_expression("field|cased|wide|contains", "cmd.exe")

    # Same literal text, different meaning, expressed only through the expression object.
    plain_contains = build_expression("field|contains", "Cmd.Exe")
    cased_contains = build_expression("field|contains|cased", "Cmd.Exe")
    assert field_literals(plain_contains) == field_literals(cased_contains) == ["Cmd.Exe"]
    assert plain_contains != cased_contains
    assert hits(plain_contains, "prefix cmd.exe suffix")
    assert not hits(cased_contains, "prefix cmd.exe suffix")


@pytest.mark.parametrize(
    "key,magic",
    [
        ("field|wide|base64offset|contains", "cmd.exe"),
        ("field|base64offset|contains", "cmd.exe"),
    ],
)
def test_generated_rule_hits_three_alignments_and_rejects_neighbouring_payloads(key, magic):
    """Build a real rule and evaluate it against positive and negative encoded logs."""
    collection = rule_detection(key, magic)

    data = magic.encode("utf-16le") if key.startswith("field|wide") else magic.encode()
    for alignment in range(3):
        sample = base64_encoded_sample(data, alignment, b"log-tail")
        assert matcher_hits(collection, sample) == 1, (alignment, sample)

    # An adjacent payload that starts two bytes later is a different string and must not hit.
    changed = bytearray(data)
    changed[0] ^= 0x01  # first byte changed, e.g. "dmd.exe" / "gmd.exe"
    for alignment in range(3):
        sample = base64_encoded_sample(bytes(changed), alignment, b"log-tail")
        assert matcher_hits(collection, sample) == 0, (alignment, sample)


def test_neighbouring_payload_differing_in_one_byte_is_rejected():
    expression = build_expression("field|base64offset|contains", "cmd.exe")
    for position in range(len("cmd.exe")):
        # Flip a bit that is covered by the fragment at every alignment. The last bytes only
        # contribute padding bits at some alignments, so restrict the check to the bytes the
        # fragment fully covers (see _covered_bytes below).
        neighbour = (
            "cmd.exe"[:position]
            + chr(ord("cmd.exe"[position]) ^ 0x04)
            + "cmd.exe"[position + 1 :]
        )
        for alignment in range(3):
            if position not in covered_byte_indices(len("cmd.exe".encode()), alignment):
                continue
            sample = base64_encoded_sample(neighbour.encode(), alignment)
            assert not hits(expression, sample), (neighbour, alignment)


def test_case_only_neighbour_is_rejected_by_case_insensitive_contains():
    # Sigma string matching is case-insensitive; verify the encoding still excludes "CMD.EXE".
    expression = build_expression("field|wide|base64offset|contains", "cmd.exe")
    data = wide_bytes("CMD.EXE")
    for alignment in range(3):
        assert not hits(expression, base64_encoded_sample(data, alignment))


@pytest.mark.parametrize(
    "key",
    [
        "field|cased|wide|contains",
        "field|cased|utf16|contains",
        "field|cased|utf16be|contains",
        "field|cased|base64|contains",
        "field|cased|base64offset|contains",
        "field|cased|wide|base64offset|contains",
    ],
)
def test_encoder_after_cased_fails_explicitly(key):
    # An encoder would hand back a plain SigmaString and silently discard the case-sensitivity
    # requested by cased. The chain must fail instead of producing a different match.
    with pytest.raises(SigmaModifiedError, match="cased"):
        SigmaDetectionItem.from_mapping(key, "cmd.exe")


### Direct modifier expression tests ###
def test_base64offset_fragments_equal_reference_for_many_values():
    # The reference oracle and the modifier must agree for representative values.
    detection_item = SigmaDetectionItem("field", [], [SigmaString("x")])
    for text in ["a", "ab", "abc", "foobar", "cmd.exe", "cmd.éxe", "日本語"]:
        modifier = SigmaBase64OffsetModifier(detection_item, [])
        result = modifier.apply(SigmaString(text))
        (expansion,) = result
        assert isinstance(expansion, SigmaExpansion)
        assert [str(value) for value in expansion.values] == base64_offset_windows(
            text.encode()
        )


def test_wide_modifier_uses_reference_encoding():
    detection_item = SigmaDetectionItem("field", [], [SigmaString("x")])
    result = SigmaWideModifier(detection_item, []).apply(SigmaString("cmd.exe"))
    (value,) = result
    assert isinstance(value, SigmaString)
    assert bytes(value) == wide_bytes("cmd.exe")


def test_contains_on_expansion_is_applied_to_each_fragment():
    detection_item = SigmaDetectionItem("field", [], [SigmaString("x")])
    fragments = SigmaBase64OffsetModifier(detection_item, []).apply(SigmaString("cmd.exe"))
    for fragment in fragments:
        wrapped = SigmaContainsModifier(detection_item, []).apply(fragment)
        (expected,) = wrapped
        assert isinstance(expected, SigmaExpansion)
        for value in expected.values:
            assert value.startswith(SpecialChars.WILDCARD_MULTI)
            assert value.endswith(SpecialChars.WILDCARD_MULTI)
