"""
Escaping regression from YAML text to final query.

The fixture tests/files/escaping_regression/path_patterns.yml is always loaded through
SigmaCollection.from_yaml, so every assertion starts from real YAML text and passes through:

1. YAML scalar parsing (plain / single-quoted / double-quoted)
2. SigmaString parsing of the resulting Python string
3. TextQueryBackend.convert_value_str rendering

Query output is evaluated by a small independent matcher implemented below. It does not call the
Sigma matcher or an external search service: it tokenizes the quoted query value with backslash
escaping, rejects a dangling escape, requires only literal bytes for '=' and 'startswith', and
turns the '*' / '?' wildcards of 'match' into an anchored regular expression. A lost escape layer
therefore shows up as a wrong event set instead of a comparison against the backend's own output.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

import pytest
import yaml

import sigma.types
from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection

FIXTURE = Path(__file__).parent / "files" / "escaping_regression" / "path_patterns.yml"

# One Windows path separator. Written as an expression so the test source does not hide
# backslash counts in raw-string visual ambiguity.
BS = "\\"


class PathEscapingTestBackend(TextQueryTestBackend):
    """
    Minimal text backend with an explicit quoted-value escaping contract.

    ':' and '\' are escaped because this backend emits quoted values in which both bytes are
    structural. The inherited test backend only escapes ':', leaving backslashes unescaped.
    """

    add_escaped: ClassVar[str] = ":" + BS


class BackslashNotEscapedBackend(PathEscapingTestBackend):
    """Mutant with the backend escape layer removed, used to prove the regression is meaningful."""

    add_escaped: ClassVar[str] = ":"


class QueryValueViolation(Exception):
    """Raised when a query value uses escape sequences that carry no defined meaning."""


def tokenize_query(query: str) -> tuple[str, list[tuple[str, str]]]:
    """
    Tokenize a query of the form CommandLine<op>"<payload>" into operator and value tokens.

    Backslashes in the payload escape exactly one following byte; a trailing backslash is rejected
    because this output syntax defines it as dangling. Unescaped '*' and '?' stay wildcard tokens,
    so an escaped literal wildcard remains distinguishable at this layer.
    """
    match = re.fullmatch(r'CommandLine(=| startswith | match )"(.*)"', query)
    if match is None:
        raise QueryValueViolation(f"query does not match the backend contract: {query!r}")
    op, payload = match.groups()

    tokens: list[tuple[str, str]] = []
    i = 0
    while i < len(payload):
        char = payload[i]
        if char == BS:
            if i + 1 >= len(payload):
                raise QueryValueViolation(f"dangling backslash in value: {query!r}")
            tokens.append(("literal", payload[i + 1]))
            i += 2
        elif char == "*":
            tokens.append(("multi", char))
            i += 1
        elif char == "?":
            tokens.append(("single", char))
            i += 1
        else:
            tokens.append(("literal", char))
            i += 1

    if op in ("=", " startswith "):
        if any(kind != "literal" for kind, _ in tokens):
            raise QueryValueViolation(f"wildcard in literal operator query: {query!r}")

    return op, tokens


def parse_quoted_value(query: str) -> tuple[str, str]:
    """Return operator and decoded literal value, rejecting wildcard in literal operators."""
    op, tokens = tokenize_query(query)
    return op, "".join(value for kind, value in tokens if kind == "literal")


def matches(query: str, event_value: str) -> bool:
    """Independent matcher for the restricted query grammar emitted by the test backend."""
    op, tokens = tokenize_query(query)
    if op == "=":
        return event_value == "".join(value for kind, value in tokens if kind == "literal")
    if op == " startswith ":
        return event_value.startswith(
            "".join(value for kind, value in tokens if kind == "literal")
        )

    pattern = "".join(
        re.escape(value) if kind == "literal" else ".*" if kind == "multi" else "."
        for kind, value in tokens
    )
    return re.fullmatch(pattern, event_value) is not None


@pytest.fixture
def collection() -> SigmaCollection:
    """Load the fixture from real YAML text, never from hand-built SigmaStrings."""
    return SigmaCollection.from_yaml(FIXTURE.read_text())


@pytest.fixture
def rules(collection: SigmaCollection) -> dict[str, object]:
    return {rule.name: rule for rule in collection.rules}


@pytest.fixture
def backend() -> PathEscapingTestBackend:
    return PathEscapingTestBackend()


def yaml_scalar(name: str) -> tuple[str | None, str]:
    """
    Return the style and Python value of the CommandLine scalar for the named rule.

    PyYAML's composer is used here so the YAML layer is asserted separately from what SigmaString
    consumed. The node style (None / "'" / '"') distinguishes plain, single- and double-quoted
    scalars.
    """
    for document in yaml.compose_all(FIXTURE.read_text(), Loader=yaml.SafeLoader):
        mapping = {key.value: value for key, value in document.value}
        if mapping["name"].value != name:
            continue
        detection = {key.value: value for key, value in mapping["detection"].value}
        selection = {key.value: value for key, value in detection["selection"].value}
        node = selection["CommandLine"]
        return node.style, node.value
    raise KeyError(name)


def sigma_string_parts(rule) -> list[str]:
    """Return SigmaString parts after YAML loading, with wildcards made explicit."""
    detection_item = rule.detection.detections["selection"].detection_items[0]
    sigma_string = detection_item.value[0]
    return [
        part if isinstance(part, str) else f"<{part.name}>" for part in sigma_string.s
    ]


QUERY_BYTES = {
    "literal_star_plain": r'CommandLine="C\:\\Windows\\System32\\evil\*.exe"',
    "literal_star_single": r'CommandLine="C\:\\Windows\\System32\\evil\*.exe"',
    "literal_star_double": r'CommandLine="C\:\\Windows\\System32\\evil\*.exe"',
    "wildcard_internal_plain": r'CommandLine match "C\:\\Windows\\System32\\*\\evil.exe"',
    "wildcard_internal_single": r'CommandLine match "C\:\\Windows\\System32\\*\\evil.exe"',
    "wildcard_internal_double": r'CommandLine match "C\:\\Windows\\System32\\*\\evil.exe"',
    "trailing_backslash_plain": r'CommandLine="C\:\\Windows\\System32\\"',
    "trailing_backslash_single": r'CommandLine="C\:\\Windows\\System32\\"',
    "trailing_backslash_double": r'CommandLine="C\:\\Windows\\System32\\"',
    "mixed_segments_plain": r'CommandLine match "C\:\\Windows\\System32\\logs\\?\\evil\*.exe"',
    "mixed_segments_single": r'CommandLine match "C\:\\Windows\\System32\\logs\\?\\evil\*.exe"',
    "mixed_segments_double": r'CommandLine match "C\:\\Windows\\System32\\logs\\?\\evil\*.exe"',
}

YAML_VALUES = {
    "literal_star": "C:" + BS + "Windows" + BS + "System32" + BS + "evil" + BS + "*" + ".exe",
    "wildcard_internal": (
        "C:" + BS + "Windows" + BS + "System32" + BS + BS + "*" + BS + "evil.exe"
    ),
    "trailing_backslash": "C:" + BS + "Windows" + BS + "System32" + BS,
    "mixed_segments": (
        "C:" + BS + "Windows" + BS + "System32" + BS + "logs" + BS + BS + "?"
        + BS + "evil" + BS + "*" + ".exe"
    ),
}

SIGMA_PARTS = {
    "literal_star": ["C:" + BS + "Windows" + BS + "System32" + BS + "evil*.exe"],
    "wildcard_internal": [
        "C:" + BS + "Windows" + BS + "System32" + BS,
        "<WILDCARD_MULTI>",
        BS + "evil.exe",
    ],
    "trailing_backslash": ["C:" + BS + "Windows" + BS + "System32" + BS],
    "mixed_segments": [
        "C:" + BS + "Windows" + BS + "System32" + BS + "logs" + BS,
        "<WILDCARD_SINGLE>",
        BS + "evil*.exe",
    ],
}

NAMES = [f"{base}_{style}" for base in YAML_VALUES for style in ("plain", "single", "double")]

EXPECTED_STYLE = {"plain": None, "single": "'", "double": '"'}


def base_name(name: str) -> str:
    return name.rsplit("_", 1)[0]


@pytest.mark.parametrize("name", NAMES)
def test_yaml_layer_distinguishes_quoting_style(name: str):
    style, value = yaml_scalar(name)
    assert style == EXPECTED_STYLE[name.rsplit("_", 1)[1]]
    assert value == YAML_VALUES[base_name(name)]


@pytest.mark.parametrize("name", NAMES)
def test_sigma_string_layer_preserves_literal_bytes(rules, name: str):
    assert sigma_string_parts(rules[name]) == SIGMA_PARTS[base_name(name)]


@pytest.mark.parametrize("name", NAMES)
def test_backend_layer_emits_stable_escaped_bytes(rules, backend, name: str):
    assert backend.convert_rule(rules[name])[0] == QUERY_BYTES[name]


def events_for(base: str) -> list[str]:
    """Event values around the semantics of one fixture pattern."""
    if base == "literal_star":
        return [
            "C:" + BS + "Windows" + BS + "System32" + BS + "evil" + "*" + ".exe",
            "C:" + BS + "Windows" + BS + "System32" + BS + "evil" + BS + "anything.exe",
            "C:" + BS + "Windows" + BS + "System32" + BS + "evil.exe",
        ]
    if base == "wildcard_internal":
        return [
            "C:" + BS + "Windows" + BS + "System32" + BS + "a" + BS + "evil.exe",
            "C:" + BS + "Windows" + BS + "System32" + BS + "a" + BS + "sub" + BS + "evil.exe",
            "C:" + BS + "Windows" + BS + "System32" + BS + "evil.exe",
        ]
    if base == "trailing_backslash":
        return [
            "C:" + BS + "Windows" + BS + "System32" + BS,
            "C:" + BS + "Windows" + BS + "System32",
            "C:" + BS + "Windows" + BS + "System32" + BS + "evil.exe",
        ]
    if base == "mixed_segments":
        return [
            "C:" + BS + "Windows" + BS + "System32" + BS + "logs" + BS + "a"
            + BS + "evil" + "*" + ".exe",
            "C:" + BS + "Windows" + BS + "System32" + BS + "logs" + BS + "a"
            + BS + "evil" + BS + "payload.exe",
            "C:" + BS + "Windows" + BS + "System32" + BS + "logs" + BS + "ab"
            + BS + "evil" + "*" + ".exe",
        ]
    raise AssertionError(base)


EXPECTED_MATCHES = {
    "literal_star": [True, False, False],
    "wildcard_internal": [True, True, False],
    "trailing_backslash": [True, False, False],
    "mixed_segments": [True, False, False],
}


@pytest.mark.parametrize("name", NAMES)
def test_query_semantics_match_only_intended_events(rules, backend, name: str):
    base = base_name(name)
    query = backend.convert_rule(rules[name])[0]
    observed = [matches(query, event) for event in events_for(base)]
    assert observed == EXPECTED_MATCHES[base]


def test_dropping_backend_escape_layer_causes_false_negative_and_false_positive(rules, backend):
    """
    Remove the backend's backslash escaping and verify the regression detects both failure modes.

    trailing_backslash: the literal payload ends in a dangling escape, so the intended event is no
    longer representable (false negative).
    wildcard_internal: '\\' + '*' in the source is escaped to the literal pair '\\*' instead of a
    wildcard, while every other backslash loses its separator meaning. An intended one-segment
    event stops matching (false negative) and a path with the wrong separators starts matching
    (false positive).
    """
    mutant = BackslashNotEscapedBackend()

    trailing = mutant.convert_rule(rules["trailing_backslash_plain"])[0]
    assert trailing == 'CommandLine="C\\:\\Windows\\System32\\"'
    with pytest.raises(QueryValueViolation, match="dangling backslash"):
        parse_quoted_value(trailing)

    wildcard = mutant.convert_rule(rules["wildcard_internal_plain"])[0]
    assert wildcard == 'CommandLine match "C\\:\\Windows\\System32\\*\\evil.exe"'
    correct_wildcard = backend.convert_rule(rules["wildcard_internal_plain"])[0]

    # Intended one-segment event: the mutant treats '*' literally and drops the separator
    # semantics of the remaining backslashes, so this becomes a false negative.
    intended = "C:" + BS + "Windows" + BS + "System32" + BS + "a" + BS + "evil.exe"
    assert matches(correct_wildcard, intended) is True
    assert matches(wildcard, intended) is False

    # Unintended event with the wrong separators: matches under the mutant but not the correct
    # query.
    unintended = "C:WindowsSystem32*evil.exe"
    assert matches(wildcard, unintended) is True
    assert matches(correct_wildcard, unintended) is False


def test_dropping_sigma_string_escape_layer_turns_literal_star_into_wildcard(
    monkeypatch, collection
):
    """
    Remove SigmaString's escape handling and verify a literal '*' starts acting as a wildcard.

    The mutation is installed before a fresh SigmaCollection.from_yaml call, so this case also
    starts from real YAML text; only the SigmaString parsing layer is deleted.
    """
    original_init = sigma.types.SigmaString.__init__

    def without_escape(self, s=None, escape=True):
        original_init(self, s, escape=False)

    monkeypatch.setattr(sigma.types.SigmaString, "__init__", without_escape)
    mutant_collection = SigmaCollection.from_yaml(FIXTURE.read_text())
    mutant_rule = {rule.name: rule for rule in mutant_collection.rules}["literal_star_plain"]
    mutant_query = PathEscapingTestBackend().convert_rule(mutant_rule)[0]

    correct_rule = {rule.name: rule for rule in collection.rules}["literal_star_plain"]
    correct_query = PathEscapingTestBackend().convert_rule(correct_rule)[0]

    payload_event = "C:" + BS + "Windows" + BS + "System32" + BS + "evil" + BS + "payload.exe"
    literal_star_event = "C:" + BS + "Windows" + BS + "System32" + BS + "evil" + "*" + ".exe"

    # The layer deletion widens the match set: 'payload.exe' now matches and the literal-star
    # filename no longer does, while the correct query has the opposite outcome.
    assert matches(mutant_query, payload_event) is True
    assert matches(correct_query, payload_event) is False
    assert matches(mutant_query, literal_star_event) is False
    assert matches(correct_query, literal_star_event) is True
