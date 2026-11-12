"""Structured provenance for Sigma filter suppressions.

When a :class:`~sigma.filters.SigmaFilter` is applied to a rule it appends a
rewritten copy of its filter condition to the rule condition and adds copies of
its detections under generated ``_filt_<random>_<identifier>`` names.  The
filtering logic itself is left completely untouched by this module; it only
attaches and reads back *provenance* describing which filter rule and which
part of its condition caused a node of the final condition tree to suppress
events.

The provenance follows the condition nodes that are actually present in the
final rule:

* only filters that matched the rule contribute a
  :class:`SuppressionSource`,
* a suppression is attached to every condition subtree that originates from a
  matched filter, including subtrees below a ``NOT`` operator and subtrees of
  filters stacked on top of each other,
* filters that did not match (different logsource, unknown rule reference,
  correlation rules) never appear in the output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule.detection import SigmaDetection

if TYPE_CHECKING:
    from sigma.exceptions import SigmaRuleLocation
    from sigma.rule.rule import SigmaRule

# Sentinel stored in ``SuppressionSource.matched_rules`` when a filter declares
# ``rules: any`` and therefore does not name a concrete referenced rule.
RULES_ANY: str = "any"

ConditionTreeNode = ConditionItem | ConditionFieldEqualsValueExpression | ConditionValueExpression


@dataclass(frozen=True)
class SuppressionSource:
    """Provenance of a suppression that was applied to a rule.

    Each instance describes one application of one
    :class:`~sigma.filters.SigmaFilter` to one rule.  The same filter applied to
    several rules therefore produces one independent source per rule, and
    several stacked filters produce several sources on the same rule.
    """

    #: Display name of the filter rule (``title`` attribute).
    filter_title: str
    #: Filter rule identifier (UUID) when the filter defines one, else ``None``.
    filter_id: str | None
    #: Filter ``name`` attribute when defined, else ``None``.
    filter_name: str | None
    #: The rule references of the filter that matched the target rule, or
    #: :data:`RULES_ANY` for a ``rules: any`` filter.
    matched_rules: list[str] | str
    #: Original, unmodified condition string from the filter definition.
    filter_condition: str
    #: Generated prefix under which the filter detections and the filter
    #: condition live inside the filtered rule.  Connects the source to the
    #: concrete ``_filt_...`` condition nodes.
    prefix: str
    #: Location of the filter rule definition when it was loaded from a file.
    filter_source: SigmaRuleLocation | None = field(default=None, compare=False)
    #: Location of the filtered rule definition when it was loaded from a file.
    rule_source: SigmaRuleLocation | None = field(default=None, compare=False)
    #: Title of the filtered rule.
    rule_title: str | None = None
    #: Identifier of the filtered rule when defined.
    rule_id: str | None = None

    @staticmethod
    def _location_to_dict(location: SigmaRuleLocation | None) -> dict[str, Any] | None:
        if location is None:
            return None
        result: dict[str, Any] = {"path": str(location.path)}
        if location.line is not None:
            result["line"] = location.line
        if location.char is not None:
            result["char"] = location.char
        return result

    def to_dict(self) -> dict[str, Any]:
        """Serialize the source into a plain data structure."""
        return {
            "filter_title": self.filter_title,
            "filter_id": self.filter_id,
            "filter_name": self.filter_name,
            "matched_rules": self.matched_rules,
            "filter_condition": self.filter_condition,
            "prefix": self.prefix,
            "filter_source": self._location_to_dict(self.filter_source),
            "rule_source": self._location_to_dict(self.rule_source),
            "rule_title": self.rule_title,
            "rule_id": self.rule_id,
        }


def _suppression_of_detection(
    node: ConditionFieldEqualsValueExpression | ConditionValueExpression,
) -> SuppressionSource | None:
    """Return the suppression attached to the detection that produced a leaf.

    Condition leaves are produced by :class:`SigmaDetectionItem` instances
    nested inside :class:`SigmaDetection` objects.  Walking up the parent chain
    reaches the named detection the leaf belongs to; filter-added detections
    carry the suppression source while the rule's own detections carry
    ``None``.
    """
    parent = node.parent
    while parent is not None and not isinstance(parent, SigmaDetection):
        parent = parent.parent
    if isinstance(parent, SigmaDetection):
        return parent.suppression
    return None


def _suppression_set(node: ConditionTreeNode) -> tuple[SuppressionSource, ...]:
    """Collect the distinct filter suppressions of all leaves below a node.

    Leaves belonging to the rule's own detections contribute nothing, so the
    result only contains sources of filter-owned leaves.
    """
    if isinstance(node, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
        suppression = _suppression_of_detection(node)
        return (suppression,) if suppression is not None else tuple()
    collected: dict[int, SuppressionSource] = {}
    for arg in node.args:
        if arg is None:
            continue
        for suppression in _suppression_set(arg):
            collected[id(suppression)] = suppression
    return tuple(collected.values())


def _is_fully_filter_owned(node: ConditionTreeNode) -> bool:
    """Check that every leaf of *node* was added by a matched filter.

    A node mixing filter leaves with rule-owned leaves (the typical top-level
    ``rule condition AND filter condition`` node) is not filter-owned itself and
    must not be reported as a suppression subtree; its filter-owned children are
    reported instead.
    """
    if isinstance(node, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
        return _suppression_of_detection(node) is not None
    return all(_is_fully_filter_owned(arg) for arg in node.args if arg is not None)


def suppression_subtrees(
    condition: ConditionTreeNode,
) -> list[tuple[ConditionTreeNode, SuppressionSource]]:
    """Return all condition subtrees that originate from a matched filter.

    Each returned pair consists of the highest node whose whole subtree belongs
    to exactly one :class:`SuppressionSource` and that source.  A parent and its
    child are both returned when the parent is a single-source node too (e.g.
    the ``NOT`` above a filter selection and the selection itself), which keeps
    the negation traceable: the source follows every applied condition node,
    not just the innermost one.

    Nodes mixing rule and filter conditions (or conditions from different
    filters) are not returned themselves; their filter-owned children are
    returned instead.  Unmatched filters have no nodes in the tree at all and
    therefore never appear.
    """
    results: list[tuple[ConditionTreeNode, SuppressionSource]] = []

    def visit(node: ConditionTreeNode) -> tuple[SuppressionSource, ...]:
        if isinstance(node, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
            sources = _suppression_set(node)
            if sources:
                results.append((node, sources[0]))
            return sources

        child_sources: list[SuppressionSource] = []
        for arg in node.args:
            if arg is None:
                continue
            child_sources.extend(visit(arg))

        unique: dict[int, SuppressionSource] = {}
        for source in child_sources:
            unique[id(source)] = source
        sources = tuple(unique.values())
        # A node is a suppression subtree only when its entire subtree belongs to
        # one filter: every leaf must be filter-owned and all leaves must share
        # the same source.
        if len(sources) == 1 and _is_fully_filter_owned(node):
            results.append((node, sources[0]))
        return sources

    visit(condition)
    return results


def suppression_provenance(
    rule: "SigmaRule",
) -> list[SuppressionSource]:
    """Return the suppression sources that are present in the rule's conditions.

    The list is ordered by application order, i.e. the order in which the
    filters were passed to :meth:`SigmaCollection.apply_filters
    <sigma.collection.SigmaCollection.apply_filters>`.  Only sources whose
    condition nodes still exist in the parsed condition tree are returned: a
    matched filter whose detections were later removed by a processing
    transformation no longer suppresses anything and therefore no longer
    appears.  The result is empty for rules without a matching filter and for
    correlation rules, which filters are never applied to.
    """
    present: set[int] = set()
    for parsed in rule.detection.parsed_condition:
        condition_tree = parsed.parsed
        if condition_tree is not None:
            present.update(id(source) for source in _suppression_set(condition_tree))
    return [
        source for source in rule.detection.suppression_sources.values() if id(source) in present
    ]


def suppression_trace(
    rule: "SigmaRule",
) -> list[dict[str, Any]]:
    """Build a serializable trace from suppression nodes back to both inputs.

    Every entry links one suppressed condition subtree to the filter rule and
    filter condition it came from together with the locations of both the
    filter rule and the filtered rule.  The condition expression is rendered as
    a compact class-based representation (``NOT``, ``AND``, ``OR`` and the leaf
    field/value expressions) so that the trace remains stable across backends.
    """

    def render(node: ConditionTreeNode) -> Any:
        if isinstance(node, ConditionFieldEqualsValueExpression):
            return {"field": node.field, "value": str(node.value)}
        if isinstance(node, ConditionValueExpression):
            return {"value": str(node.value)}
        rendered_args = [render(arg) for arg in node.args if arg is not None]
        if isinstance(node, ConditionNOT):
            return {"NOT": rendered_args}
        if isinstance(node, ConditionAND):
            return {"AND": rendered_args}
        if isinstance(node, ConditionOR):
            return {"OR": rendered_args}
        return rendered_args

    traces: list[dict[str, Any]] = []
    for condition_index, parsed in enumerate(rule.detection.parsed_condition):
        condition_tree = parsed.parsed
        if condition_tree is None:
            continue
        for node, source in suppression_subtrees(condition_tree):
            traces.append(
                {
                    "rule_condition_index": condition_index,
                    "condition_node": render(node),
                    "source": source.to_dict(),
                }
            )
    return traces
