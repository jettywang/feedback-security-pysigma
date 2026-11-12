"""
Conservative offline comparison of two versions of a Sigma rule.

This module answers one question for rule reviewers: does an update to a Sigma
rule expand, narrow, or keep the set of events it alerts on, given that both
versions are processed by the *same* processing pipeline (field mappings etc.
are applied before any comparison takes place)?

The comparison is deliberately conservative and fully offline:

* Supported detection semantics are limited to plain string equality
  (``field: value`` without modifiers), OR-linked value lists (set semantics),
  and conditions composed from identifiers with ``and``/``or`` (including
  ``1 of them`` / ``all of them``).
* Anything else - regular expressions, value modifiers (``contains``,
  ``re``, ``all``, ...), keyword detections, ``not`` in conditions, patterned
  selectors (``1 of selection_*``), correlation rules, differing log sources -
  makes the comparison return ``unknown`` instead of guessing.
* Every ``expands``/``narrows`` verdict is backed by a distinguishing event: a
  concrete field/value assignment that matches one version but not the other.
  The event is re-verified by evaluation before it is reported, so the verdict
  can be checked independently with :func:`event_matches_rule`.

No online services or models are involved.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field as dataclass_field
from enum import Enum
from typing import Any, Iterable

from sigma.conditions import (
    ConditionAND,
    ConditionIdentifier,
    ConditionItem,
    ConditionOR,
    ConditionSelector,
)
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.rule.base import SigmaRuleBase
from sigma.rule.detection import SigmaDetection, SigmaDetectionItem
from sigma.types import SigmaString


class Relation(Enum):
    """Provable relation between the alert scope of two rule versions."""

    EQUIVALENT = "equivalent"  # both versions match exactly the same events
    EXPANDS = "expands"  # new version matches a strict superset of the old
    NARROWS = "narrows"  # new version matches a strict subset of the old
    UNKNOWN = "unknown"  # no relation could be proven


@dataclass
class MetadataChange:
    """A single changed rule attribute that does not affect matching semantics."""

    field: str
    old: Any
    new: Any

    def to_dict(self) -> dict[str, Any]:
        return {"field": self.field, "old": self.old, "new": self.new}


@dataclass
class ComparisonResult:
    """Outcome of comparing two rule versions."""

    relation: Relation
    reason: str
    metadata_changes: list[MetadataChange] = dataclass_field(default_factory=list)
    unsupported: list[str] = dataclass_field(default_factory=list)
    distinguishing_event: dict[str, str] | None = None
    event_matches_old: bool | None = None
    event_matches_new: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "relation": self.relation.value,
            "reason": self.reason,
            "metadata_changes": [change.to_dict() for change in self.metadata_changes],
            "unsupported": list(self.unsupported),
            "distinguishing_event": self.distinguishing_event,
            "event_matches_old": self.event_matches_old,
            "event_matches_new": self.event_matches_new,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


# --- Internal formula representation ---------------------------------------
#
# A formula is a boolean combination of atoms. An atom (field, values) matches
# an event iff the event carries exactly this field with a value contained in
# the atom's value set. Only positive formulas exist here; negation is
# unsupported and rejected during extraction.


@dataclass(frozen=True)
class _Atom:
    field: str
    values: frozenset[str]


@dataclass(frozen=True)
class _And:
    args: tuple[Any, ...]


@dataclass(frozen=True)
class _Or:
    args: tuple[Any, ...]


_MAX_DNF_TERMS = 4096  # guard against exponential blow-up of nested AND/OR
_MAX_WITNESS_BRANCHES = 10000  # guard witness search


class _Unsupported(Exception):
    """Raised when a rule construct cannot be mapped into the supported fragment."""


class _TooLarge(Exception):
    """Raised when a formula exceeds the conservative size limits."""


def _detection_item_to_formula(item: SigmaDetectionItem) -> Any:
    if item.field is None:
        raise _Unsupported("keyword detection without field is not supported")
    if item.negated:
        raise _Unsupported(f"negated detection item on field '{item.field}' is not supported")
    if item.modifiers:
        names = ", ".join(modifier.__name__ for modifier in item.modifiers)
        raise _Unsupported(
            f"unsupported modifier(s) on field '{item.field}': {names}"
        )
    values: list[str] = []
    for value in item.value:
        if not isinstance(value, SigmaString):
            raise _Unsupported(
                f"non-string value of type {type(value).__name__} on field "
                f"'{item.field}' is not supported"
            )
        if value.contains_special():
            raise _Unsupported(
                f"wildcards in value '{value.original}' on field '{item.field}' are not supported"
            )
        if value.contains_placeholder():
            raise _Unsupported(
                f"placeholder in value '{value.original}' on field '{item.field}' is not supported"
            )
        values.append(str(value))
    if not values:
        raise _Unsupported(f"empty value list on field '{item.field}' is not supported")
    if item.value_linking is ConditionAND:
        # Defensive: unreachable without modifiers, kept for completeness.
        return _And(tuple(_Atom(item.field, frozenset([v])) for v in values))
    return _Atom(item.field, frozenset(values))


def _detection_to_formula(detection: SigmaDetection | SigmaDetectionItem) -> Any:
    if isinstance(detection, SigmaDetectionItem):
        return _detection_item_to_formula(detection)
    formulas = tuple(_detection_to_formula(item) for item in detection.detection_items)
    if detection.item_linking is ConditionAND:
        return _And(formulas)
    return _Or(formulas)


def _condition_to_formula(node: ConditionItem, detections: dict[str, SigmaDetection]) -> Any:
    if isinstance(node, ConditionAND):
        return _And(tuple(_condition_to_formula(arg, detections) for arg in node.args))
    if isinstance(node, ConditionOR):
        return _Or(tuple(_condition_to_formula(arg, detections) for arg in node.args))
    if isinstance(node, ConditionIdentifier):
        try:
            detection = detections[node.identifier]
        except KeyError:
            raise _Unsupported(f"condition references unknown detection '{node.identifier}'")
        return _detection_to_formula(detection)
    if isinstance(node, ConditionSelector):
        if node.pattern != "them":
            raise _Unsupported(
                f"patterned condition selector '{node.pattern}' is not supported"
            )
        formulas = tuple(_detection_to_formula(detection) for detection in detections.values())
        if node.cond_class is ConditionAND:
            return _And(formulas)
        return _Or(formulas)
    raise _Unsupported(
        f"condition element of type {type(node).__name__} is not supported"
    )


def _merge_terms(
    left: dict[str, frozenset[str]], right: dict[str, frozenset[str]]
) -> dict[str, frozenset[str]] | None:
    """Conjoin two DNF terms; returns None if the conjunction is unsatisfiable."""
    merged = dict(left)
    for field_name, values in right.items():
        if field_name in merged:
            intersection = merged[field_name] & values
            if not intersection:
                return None
            merged[field_name] = intersection
        else:
            merged[field_name] = values
    return merged


def _to_dnf(formula: Any) -> list[dict[str, frozenset[str]]]:
    """Convert a formula to DNF: a list of terms, each mapping field -> value set."""
    if isinstance(formula, _Atom):
        return [{formula.field: formula.values}]
    if isinstance(formula, _Or):
        terms: list[dict[str, frozenset[str]]] = []
        for arg in formula.args:
            terms.extend(_to_dnf(arg))
            if len(terms) > _MAX_DNF_TERMS:
                raise _TooLarge("formula exceeds DNF term limit")
        return terms
    if isinstance(formula, _And):
        terms = [dict()]
        for arg in formula.args:
            arg_terms = _to_dnf(arg)
            combined: list[dict[str, frozenset[str]]] = []
            for term in terms:
                for arg_term in arg_terms:
                    merged = _merge_terms(term, arg_term)
                    if merged is not None:
                        combined.append(merged)
            terms = combined
            if len(terms) > _MAX_DNF_TERMS:
                raise _TooLarge("formula exceeds DNF term limit")
        return terms
    raise _Unsupported(f"cannot normalize formula element of type {type(formula).__name__}")


def _term_implies(term: dict[str, frozenset[str]], other: dict[str, frozenset[str]]) -> bool:
    """Conservative term implication: every atom of other is covered by term."""
    return all(
        field_name in term and term[field_name] <= values
        for field_name, values in other.items()
    )


_MAX_COVERAGE_SPLITS = 10000  # budget for the recursive coverage check


def _term_covered(
    term: dict[str, frozenset[str]],
    others: list[dict[str, frozenset[str]]],
    budget: list[int],
) -> bool:
    """
    Sound (but incomplete) check whether every event matching term also matches
    at least one term of others.

    Only terms of others that bind fields also bound by term can cover events
    of term (an event of term may lack any other field), and only where the
    value sets intersect. Coverage is established either by a single covering
    term or by partitioning the value set of one field and recursing on both
    parts. Every step is sound; giving up (budget exhausted, no productive
    split) returns False, which the caller treats as "cannot prove".
    """
    if budget[0] <= 0:
        return False
    budget[0] -= 1
    relevant = [
        other
        for other in others
        if all(field_name in term for field_name in other)
        and all(term[field_name] & other[field_name] for field_name in other)
    ]
    if any(_term_implies(term, other) for other in relevant):
        return True
    # Partition the term on a field where a relevant other-term cuts its values.
    for other in relevant:
        for field_name, values in other.items():
            intersection = term[field_name] & values
            rest = term[field_name] - values
            if intersection and rest:
                head = dict(term)
                head[field_name] = intersection
                tail = dict(term)
                tail[field_name] = rest
                return _term_covered(head, others, budget) and _term_covered(
                    tail, others, budget
                )
    return False


def _dnf_implies(
    dnf: list[dict[str, frozenset[str]]], other: list[dict[str, frozenset[str]]]
) -> bool:
    """Sound (but incomplete) implication check between two DNF formulas."""
    budget = [_MAX_COVERAGE_SPLITS]
    return all(_term_covered(term, other, budget) for term in dnf)


def _term_matches(term: dict[str, frozenset[str]], event: dict[str, str]) -> bool:
    return all(
        field_name in event and event[field_name] in values
        for field_name, values in term.items()
    )


def _dnf_matches(dnf: list[dict[str, frozenset[str]]], event: dict[str, str]) -> bool:
    return any(_term_matches(term, event) for term in dnf)


def _find_distinguishing_event(
    dnf: list[dict[str, frozenset[str]]], other: list[dict[str, frozenset[str]]]
) -> dict[str, str] | None:
    """
    Find an event that matches dnf but not other, or None if the (bounded)
    search fails. Any returned event is verified by evaluation, so a result is
    always a sound proof of non-inclusion.
    """
    branches = [0]

    def violate(
        assignment: dict[str, str],
        source_term: dict[str, frozenset[str]],
        others: list[dict[str, frozenset[str]]],
        index: int,
    ) -> dict[str, str] | None:
        """Extend assignment so that every term of others (from index on) is violated."""
        if branches[0] > _MAX_WITNESS_BRANCHES:
            return None
        if index == len(others):
            return assignment
        other_term = others[index]
        # An atom on a field the source term does not bind can never be
        # satisfied by the event: the term is already violated.
        if any(field_name not in source_term for field_name in other_term):
            return violate(assignment, source_term, others, index + 1)
        # An atom already falsified by the current assignment violates the term.
        if any(
            field_name in assignment and assignment[field_name] not in values
            for field_name, values in other_term.items()
        ):
            return violate(assignment, source_term, others, index + 1)
        # Branch: falsify one still-unassigned atom of the term.
        for field_name, values in other_term.items():
            if field_name in assignment:
                continue
            for value in sorted(source_term[field_name] - values):
                branches[0] += 1
                if branches[0] > _MAX_WITNESS_BRANCHES:
                    return None
                extended = dict(assignment)
                extended[field_name] = value
                result = violate(extended, source_term, others, index)
                if result is not None:
                    return result
        return None

    for source_term in dnf:
        if any(_term_implies(source_term, other_term) for other_term in other):
            continue  # this disjunct is fully covered by the other formula
        event = violate({}, source_term, other, 0)
        if event is None:
            continue
        for field_name, values in source_term.items():
            event.setdefault(field_name, sorted(values)[0])
        # Restrict the event to fields of the source term: extra fields would
        # only restrict matching further, but keep it minimal and exact.
        event = {field_name: event[field_name] for field_name in source_term}
        if _dnf_matches(dnf, event) and not _dnf_matches(other, event):
            return event
    return None


# --- Rule loading and metadata ---------------------------------------------

_METADATA_EXCLUDED_KEYS = {"detection", "logsource"}


def _load_rule(rule: str | SigmaRuleBase) -> SigmaRuleBase:
    if isinstance(rule, SigmaRuleBase):
        return rule
    collection = SigmaCollection.from_yaml(rule)
    rules = list(collection.rules)
    if len(rules) != 1:
        raise _Unsupported(
            f"expected exactly one rule per document, found {len(rules)}"
        )
    return rules[0]


def _json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return str(value)


def _metadata_changes(old: SigmaRule, new: SigmaRule) -> list[MetadataChange]:
    old_dict = old.to_dict()
    new_dict = new.to_dict()
    changes = []
    for key in sorted(set(old_dict) | set(new_dict)):
        if key in _METADATA_EXCLUDED_KEYS:
            continue
        old_value, new_value = old_dict.get(key), new_dict.get(key)
        if old_value != new_value:
            changes.append(
                MetadataChange(field=key, old=_json_safe(old_value), new=_json_safe(new_value))
            )
    return changes


def _logsources_equal(old: SigmaRule, new: SigmaRule) -> bool:
    return old.logsource.to_dict() == new.logsource.to_dict()


# --- Public API --------------------------------------------------------------


@dataclass
class _ExtractedRule:
    rule: SigmaRule
    dnf: list[dict[str, frozenset[str]]]


def _extract(rule: SigmaRule, pipeline: ProcessingPipeline | None) -> _ExtractedRule:
    processed = copy.deepcopy(rule)
    if pipeline is not None:
        pipeline.apply(processed)
    detections = processed.detection
    if len(detections.parsed_condition) != 1:
        raise _Unsupported(
            f"expected exactly one condition, found {len(detections.parsed_condition)}"
        )
    condition_tree = detections.parsed_condition[0].parse(postprocess=False)
    if condition_tree is None:
        raise _Unsupported("condition could not be parsed")
    formula = _condition_to_formula(condition_tree, detections.detections)
    return _ExtractedRule(rule=processed, dnf=_to_dnf(formula))


def compare_rules(
    old: str | SigmaRuleBase,
    new: str | SigmaRuleBase,
    pipeline: ProcessingPipeline | None = None,
) -> ComparisonResult:
    """
    Conservatively compare two versions of a Sigma rule.

    Both versions are processed by the same (optional) processing pipeline
    before comparison, so field mappings are reflected in the result. The
    returned relation is one of equivalent / expands / narrows / unknown;
    expands and narrows carry a distinguishing event as verifiable evidence.
    """
    try:
        old_rule = _load_rule(old)
        new_rule = _load_rule(new)
    except (_Unsupported, SigmaError) as e:
        return ComparisonResult(
            Relation.UNKNOWN, f"failed to load rules: {e}", unsupported=[str(e)]
        )

    if isinstance(old_rule, SigmaCorrelationRule) or isinstance(new_rule, SigmaCorrelationRule):
        return ComparisonResult(
            Relation.UNKNOWN,
            "correlation rules are not supported; no relation can be proven",
            unsupported=["correlation rule"],
        )

    metadata = _metadata_changes(old_rule, new_rule)

    if not _logsources_equal(old_rule, new_rule):
        return ComparisonResult(
            Relation.UNKNOWN,
            "log sources differ; alert scope relation cannot be proven",
            metadata_changes=metadata,
            unsupported=["differing logsource"],
        )

    try:
        old_extracted = _extract(old_rule, pipeline)
        new_extracted = _extract(new_rule, pipeline)
    except _Unsupported as e:
        return ComparisonResult(
            Relation.UNKNOWN,
            f"rule uses constructs outside the supported fragment: {e}",
            metadata_changes=metadata,
            unsupported=[str(e)],
        )
    except (_TooLarge, SigmaError) as e:
        return ComparisonResult(
            Relation.UNKNOWN,
            f"comparison not decidable within conservative limits: {e}",
            metadata_changes=metadata,
            unsupported=[str(e)],
        )

    old_dnf, new_dnf = old_extracted.dnf, new_extracted.dnf
    old_implies_new = _dnf_implies(old_dnf, new_dnf)
    new_implies_old = _dnf_implies(new_dnf, old_dnf)

    if old_implies_new and new_implies_old:
        return ComparisonResult(
            Relation.EQUIVALENT,
            "detection logic is logically equivalent; only metadata differs"
            if metadata
            else "rules are logically equivalent",
            metadata_changes=metadata,
        )

    if old_implies_new:
        event = _find_distinguishing_event(new_dnf, old_dnf)
        if event is not None:
            return ComparisonResult(
                Relation.EXPANDS,
                "new version matches everything the old version matches, plus more",
                metadata_changes=metadata,
                distinguishing_event=event,
                event_matches_old=_dnf_matches(old_dnf, event),
                event_matches_new=_dnf_matches(new_dnf, event),
            )
        return ComparisonResult(
            Relation.UNKNOWN,
            "old version is included in new version, but no distinguishing event "
            "could be constructed to prove strictness",
            metadata_changes=metadata,
        )

    if new_implies_old:
        event = _find_distinguishing_event(old_dnf, new_dnf)
        if event is not None:
            return ComparisonResult(
                Relation.NARROWS,
                "new version matches a strict subset of the old version",
                metadata_changes=metadata,
                distinguishing_event=event,
                event_matches_old=_dnf_matches(old_dnf, event),
                event_matches_new=_dnf_matches(new_dnf, event),
            )
        return ComparisonResult(
            Relation.UNKNOWN,
            "new version is included in old version, but no distinguishing event "
            "could be constructed to prove strictness",
            metadata_changes=metadata,
        )

    # Neither inclusion is provable. Try to exhibit distinguishing events in
    # both directions as evidence of incomparability.
    evidence = []
    event_new_only = _find_distinguishing_event(new_dnf, old_dnf)
    event_old_only = _find_distinguishing_event(old_dnf, new_dnf)
    if event_new_only is not None and event_old_only is not None:
        reason = (
            "rules are incomparable: each version matches events the other does not "
            f"(only-new: {event_new_only}, only-old: {event_old_only})"
        )
    else:
        reason = "no provable relation between the rule versions"
    return ComparisonResult(
        Relation.UNKNOWN,
        reason,
        metadata_changes=metadata,
        unsupported=evidence,
    )


def event_matches_rule(
    rule: str | SigmaRuleBase,
    event: dict[str, str],
    pipeline: ProcessingPipeline | None = None,
) -> bool:
    """
    Independently verify whether an event matches a rule version within the
    supported fragment. Raises SigmaError if the rule cannot be loaded or uses
    constructs outside the supported fragment.
    """
    loaded = _load_rule(rule)
    try:
        extracted = _extract(loaded, pipeline)
    except _Unsupported as e:
        raise SigmaError(f"rule is outside the supported fragment: {e}")
    return _dnf_matches(extracted.dnf, event)


def main(argv: Iterable[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Conservatively compare two versions of a Sigma rule (offline)."
    )
    parser.add_argument("old", help="path to the old rule YAML file")
    parser.add_argument("new", help="path to the new rule YAML file")
    parser.add_argument(
        "--pipeline",
        help="path to a processing pipeline YAML file applied to both versions before comparison",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    with open(args.old) as f:
        old_yaml = f.read()
    with open(args.new) as f:
        new_yaml = f.read()
    pipeline = None
    if args.pipeline:
        with open(args.pipeline) as f:
            pipeline = ProcessingPipeline.from_yaml(f.read())

    result = compare_rules(old_yaml, new_yaml, pipeline)
    print(result.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
