from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Literal

from typing import Self
from typing import ClassVar, cast
from pyparsing import (
    Word,
    alphas,
    alphanums,
    Keyword,
    infix_notation,
    opAssoc,
    ParseResults,
    ParseException,
)
from abc import ABC

import sigma.exceptions as sigma_exceptions
from sigma.conditions import unwrap_parse_result_operand
from sigma.exceptions import SigmaRuleLocation, SigmaTimespanError
from sigma.processing.tracking import ProcessingItemTrackingMixin
from sigma.rule import EnumLowercaseStringMixin, SigmaRule, SigmaRuleBase

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sigma.collection import SigmaCollection
    from sigma.policy import SigmaPolicy


class SigmaCorrelationType(EnumLowercaseStringMixin, Enum):
    """
    Supported correlation types.
    """

    EVENT_COUNT = auto()
    VALUE_COUNT = auto()
    TEMPORAL = auto()
    TEMPORAL_ORDERED = auto()
    VALUE_SUM = auto()
    VALUE_AVG = auto()
    VALUE_PERCENTILE = auto()
    VALUE_MEDIAN = auto()


# TODO: type supported from 3.12
# type SigmaCorrelationTypeLiteral = Literal[
SigmaCorrelationTypeLiteral = Literal[
    "event_count",
    "value_count",
    "temporal",
    "temporal_ordered",
    "temporal_extended",
    "temporal_ordered_extended",
    "value_sum",
    "value_avg",
    "value_percentile",
    "value_median",
]


@dataclass(unsafe_hash=True)
class SigmaRuleReference:
    """
    Reference to a Sigma rule. Initially this only contains the plain reference as string that is
    then resolved into a rule reference.
    """

    reference: str
    rule: SigmaRule | SigmaCorrelationRule = field(init=False, repr=False, compare=False)

    def resolve(self, rule_collection: SigmaCollection) -> None:
        """
        Resolves the reference to the actual Sigma rule.

        Raises:
            sigma_exceptions.SigmaRuleNotFoundError: If the referenced rule cannot be found in the given rule collection.
        """
        self.rule = rule_collection[self.reference]

    @classmethod
    def from_parsed(cls, s: str, l: int, t: ParseResults) -> list["SigmaRuleReference"]:
        """Create rule reference from parse result (for pyparsing integration)."""
        return [cls(t[0])]


class SigmaCorrelationConditionOperator(Enum):
    LT = auto()
    LTE = auto()
    GT = auto()
    GTE = auto()
    EQ = auto()
    NEQ = auto()

    @classmethod
    def operators(cls) -> set[str]:
        return {op.name.lower() for op in cls}


@dataclass
class SigmaCorrelationCondition:
    op: SigmaCorrelationConditionOperator
    count: int | float
    fieldref: str | list[str] | None = field(default=None)
    percentile: int | None = field(default=None)
    source: SigmaRuleLocation | None = field(default=None, compare=False)

    @classmethod
    def from_dict(
        cls: type[Self],
        d: dict[str, Any],
        source: SigmaRuleLocation | None = None,
    ) -> Self:
        d_keys = frozenset(d.keys())
        ops = frozenset(SigmaCorrelationConditionOperator.operators())
        if len(d_keys.intersection(ops)) != 1:
            raise sigma_exceptions.SigmaCorrelationConditionError(
                "Sigma correlation condition must have exactly one condition item", source=source
            )
        unknown_keys = d_keys.difference(ops).difference({"field", "percentile"})
        if unknown_keys:
            raise sigma_exceptions.SigmaCorrelationConditionError(
                "Sigma correlation condition contains invalid items: " + ", ".join(unknown_keys),
                source=source,
            )

        # Condition operator and count
        for (
            op
        ) in (
            SigmaCorrelationConditionOperator.operators()
        ):  # It's already tested above if there's an operator.
            if op in d:
                cond_op = SigmaCorrelationConditionOperator[op.upper()]
                cond_count: int | float
                try:
                    # integers stay exact; fractions are for metric thresholds
                    if isinstance(d[op], int):
                        cond_count = int(d[op])
                    else:
                        cond_count = float(d[op])
                        if not math.isfinite(cond_count):
                            raise ValueError
                        if cond_count.is_integer():
                            cond_count = int(cond_count)
                except (TypeError, ValueError):
                    raise sigma_exceptions.SigmaCorrelationConditionError(
                        f"'{ d[op] }' is no valid Sigma correlation condition count", source=source
                    )
                break

        # Condition field
        try:
            cond_field = d["field"]
        except KeyError:
            cond_field = None

        # Condition percentile (for value_percentile correlation type)
        try:
            cond_percentile = int(d["percentile"])
        except KeyError:
            cond_percentile = None
        except ValueError:
            raise sigma_exceptions.SigmaCorrelationConditionError(
                f"'{ d['percentile'] }' is no valid Sigma correlation condition percentile",
                source=source,
            )

        return cls(
            op=cond_op,
            count=cond_count,
            fieldref=cond_field,
            percentile=cond_percentile,
            source=source,
        )

    def to_dict(self: Self) -> dict[str, Any]:
        result: dict[str, Any] = {self.op.name.lower(): self.count}
        if self.fieldref:
            result["field"] = self.fieldref
        if self.percentile is not None:
            result["percentile"] = self.percentile
        return result


# Correlation condition parse tree classes
@dataclass
class CorrelationConditionItem(ABC):
    """Base class for correlation condition parse tree items."""

    arg_count: ClassVar[int]
    args: list[SigmaRuleReference | "CorrelationConditionItem"]

    @classmethod
    def from_parsed(
        cls,
        s: str,
        l: int,
        t: ParseResults | list[SigmaRuleReference | "CorrelationConditionItem"],
    ) -> list["CorrelationConditionItem"]:
        """Create condition object from parse result."""
        args: list[SigmaRuleReference | CorrelationConditionItem]
        if cls.arg_count == 1:
            # Unary operator (NOT)
            if isinstance(t, ParseResults):
                operand = unwrap_parse_result_operand(
                    t[0][-1],
                    error_class=sigma_exceptions.SigmaCorrelationConditionError,
                    error_message="Invalid wrapped correlation condition operand",
                )
                if operand is None:
                    raise sigma_exceptions.SigmaCorrelationConditionError(
                        "Invalid wrapped correlation condition operand"
                    )
                args = [operand]
            else:
                args = [t[-1]]
        elif cls.arg_count > 1:
            # Binary operators (AND, OR) - handle flat lists from pyparsing
            if isinstance(t, ParseResults):
                args = []
                for a in t[0][0::2]:
                    operand = unwrap_parse_result_operand(
                        a,
                        error_class=sigma_exceptions.SigmaCorrelationConditionError,
                        error_message="Invalid wrapped correlation condition operand",
                    )
                    if operand is None:
                        raise sigma_exceptions.SigmaCorrelationConditionError(
                            "Invalid wrapped correlation condition operand"
                        )
                    args.append(operand)
            else:
                args = t[0::2]
        else:
            args = list()
        return [cls(args)]


@dataclass
class CorrelationConditionOR(CorrelationConditionItem):
    """OR operator in correlation condition."""

    arg_count: ClassVar[int] = 2


@dataclass
class CorrelationConditionAND(CorrelationConditionItem):
    """AND operator in correlation condition."""

    arg_count: ClassVar[int] = 2


@dataclass
class CorrelationConditionNOT(CorrelationConditionItem):
    """NOT operator in correlation condition."""

    arg_count: ClassVar[int] = 1


@dataclass
class SigmaExtendedCorrelationCondition:
    """
    Extended correlation condition supporting boolean expressions with 'and', 'or', and 'not' operators.
    Uses pyparsing to parse the condition string into a structured representation.
    """

    expression: str
    source: SigmaRuleLocation | None = field(default=None, compare=False)
    _parsed: CorrelationConditionItem | SigmaRuleReference = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self: Self) -> None:
        """Parse and validate the extended condition expression."""
        try:
            self._parsed = self.parse(self.expression)
        except ParseException as e:
            raise sigma_exceptions.SigmaCorrelationConditionError(
                f"Failed to parse extended condition expression: {str(e)}",
                source=self.source,
            )

    @classmethod
    def parse(cls, expression: str) -> CorrelationConditionItem | SigmaRuleReference:
        """
        Parse an extended correlation condition expression.

        Grammar:
            rule_identifier: Word(alphas + "_", alphanums + "_")
            and_operator: Keyword("and")
            or_operator: Keyword("or")
            not_operator: Keyword("not")
            expr: infix_notation with standard precedence (not > and > or)

        Returns:
            Parse tree with CorrelationCondition* objects.
        """
        # Define rule identifier - starts with letter or underscore, followed by alphanumerics or underscores
        rule_identifier = Word(alphas + "_", alphanums + "_")
        rule_identifier.set_parse_action(SigmaRuleReference.from_parsed)

        # Define expression using infix notation
        # Precedence: not (highest) > and > or (lowest)
        expr = infix_notation(  # type: ignore[no-untyped-call]
            rule_identifier,
            [
                (Keyword("not"), 1, opAssoc.RIGHT, CorrelationConditionNOT.from_parsed),
                (Keyword("and"), 2, opAssoc.LEFT, CorrelationConditionAND.from_parsed),
                (Keyword("or"), 2, opAssoc.LEFT, CorrelationConditionOR.from_parsed),
            ],
        )

        result = expr.parse_string(expression, parse_all=True)
        return cast(CorrelationConditionItem | SigmaRuleReference, result[0])

    @property
    def parsed(self) -> CorrelationConditionItem | SigmaRuleReference:
        """Return the parsed correlation condition tree."""
        return self._parsed

    def get_referenced_rules(self) -> list[str]:
        """
        Extract all rule identifiers referenced in the condition expression in order of appearance.
        Traverses the parse tree to find all SigmaRuleReference leaf nodes.

        Returns:
            List of unique rule identifier strings in the order they first appear.
        """
        seen = set()
        referenced = []

        def traverse(node: CorrelationConditionItem | SigmaRuleReference) -> None:
            """Recursively traverse the parse tree to find rule references."""
            if isinstance(node, SigmaRuleReference):
                # Leaf node - extract the rule reference
                if node.reference not in seen:
                    seen.add(node.reference)
                    referenced.append(node.reference)
            elif isinstance(node, CorrelationConditionItem):
                # Internal node - traverse children
                for arg in node.args:
                    traverse(arg)

        traverse(self._parsed)
        return referenced

    def to_dict(self: Self) -> str:
        """Return the expression string for serialization."""
        return self.expression


@dataclass
class SigmaCorrelationTimespan:
    spec: str = field(compare=False)
    seconds: int = field(init=False)
    count: int = field(init=False)
    unit: str = field(init=False)

    timespan_re: ClassVar[re.Pattern[str]] = re.compile("(?P<count>[0-9]+)(?P<unit>[smhdwMy])")
    unit_seconds: ClassVar[dict[str, int]] = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
        "w": 604800,
        "M": 2629746,
        "y": 31556952,
    }

    def __post_init__(self: Self) -> None:
        """
        Parses a string representing a time span and stores the equivalent number of seconds.

        A time span must be a positive integer count followed by one of the unit characters
        s, m, h, d, w, M or y.

        Raises:
            sigma_exceptions.SigmaTimespanError: If the given time span is invalid.
        """
        parsed = self.timespan_re.fullmatch(self.spec) if isinstance(self.spec, str) else None
        if parsed is None:
            raise sigma_exceptions.SigmaTimespanError(f"Timespan '{ self.spec }' is invalid.")
        count = int(parsed.group("count"))
        if count <= 0:
            raise sigma_exceptions.SigmaTimespanError(
                f"Timespan '{ self.spec }' must be greater than zero."
            )
        self.count = count
        self.unit = parsed.group("unit")
        self.seconds = self.count * self.unit_seconds[self.unit]


class SigmaCorrelationWindowMode(EnumLowercaseStringMixin, Enum):
    """
    Time window semantics that a backend can express for correlation rules.

    * SLIDING: every new event is evaluated against all events of the same group within the
      preceding timespan. This is the reference semantics used by
      :class:`~sigma.matching.SigmaCorrelationRuleMatcher` and by the Sigma correlation rule
      specification.
    * FIXED: events are evaluated in fixed, pre-aligned time buckets. A fixed bucket is not
      equivalent to a sliding window: two events within the requested timespan but in adjacent
      buckets are not correlated.
    """

    SLIDING = auto()
    FIXED = auto()


# Marker retained on approximated correlation conversions. Consumers can use it to ensure that a
# query is not treated as an exact implementation of the Sigma correlation semantics.
SIGMA_TIMESPAN_APPROXIMATION_MARKER = "timespan-approximated"


@dataclass(frozen=True)
class SigmaCorrelationTimespanCapability:
    """
    Declares how a backend can represent correlation rule timespans.

    Attributes:
        min_unit: Smallest timespan unit the backend can represent. Must be one of the units
            supported by :class:`SigmaCorrelationTimespan` (``s``, ``m``, ``h``, ``d``, ``w``,
            ``M`` or ``y``). ``None`` means the backend did not restrict the minimum unit.
        window_modes: Time window semantics the backend can express. An empty set means the
            backend did not declare a mode. A backend capable of both semantics should declare
            both; conversion prefers SLIDING because that matches the Sigma reference semantics.
        declared: Whether the backend actually declared capability information. If False, the
            backend follows the legacy behavior and no timespan checks are enforced.
    """

    min_unit: str | None = None
    window_modes: frozenset[SigmaCorrelationWindowMode] = field(default_factory=frozenset)
    declared: bool = True

    def __post_init__(self: Self) -> None:
        if self.min_unit is not None and self.min_unit not in SigmaCorrelationTimespan.unit_seconds:
            raise sigma_exceptions.SigmaValueError(
                f"Invalid correlation timespan minimum unit '{self.min_unit}', must be one of: "
                + ", ".join(SigmaCorrelationTimespan.unit_seconds)
            )

        coerced_modes: set[SigmaCorrelationWindowMode] = set()
        for mode in self.window_modes:
            if isinstance(mode, SigmaCorrelationWindowMode):
                coerced_modes.add(mode)
            elif isinstance(mode, str):
                try:
                    coerced_modes.add(SigmaCorrelationWindowMode[mode.upper()])
                except KeyError:
                    raise sigma_exceptions.SigmaValueError(
                        f"Invalid correlation window mode '{mode}', must be one of: sliding, fixed"
                    )
            else:
                raise sigma_exceptions.SigmaValueError(f"Invalid correlation window mode {mode!r}")
        object.__setattr__(self, "window_modes", frozenset(coerced_modes))

    @classmethod
    def undeclared(cls: type[Self]) -> Self:
        """Create a capability object for backends that do not declare timespan support."""
        return cls(min_unit=None, window_modes=frozenset(), declared=False)

    @property
    def min_unit_seconds(self: Self) -> int | None:
        """Return the minimum representable unit in seconds or None if unrestricted."""
        if self.min_unit is None:
            return None
        return SigmaCorrelationTimespan.unit_seconds[self.min_unit]

    @property
    def supports_sliding(self: Self) -> bool:
        return SigmaCorrelationWindowMode.SLIDING in self.window_modes

    @property
    def supports_fixed(self: Self) -> bool:
        return SigmaCorrelationWindowMode.FIXED in self.window_modes

    def supports_duration(self: Self, seconds: int) -> bool:
        """Return True if the duration can be represented exactly with the minimum unit."""
        if self.min_unit_seconds is None:
            return True
        return seconds > 0 and seconds % self.min_unit_seconds == 0

    def to_dict(self: Self) -> dict[str, Any]:
        return {
            "min_unit": self.min_unit,
            "window_modes": sorted(str(mode) for mode in self.window_modes),
            "declared": self.declared,
        }


@dataclass(frozen=True)
class SigmaCorrelationTimespanResolution:
    """
    Result of checking a correlation rule timespan against backend capabilities.

    Attributes:
        requested: The timespan requested by the rule.
        capability: The capability declaration against which the timespan was checked.
        window_mode: The window mode selected for conversion. ``None`` if the backend did not
            declare one.
        effective_seconds: The window width the generated query actually implements.
        effective_count: Count of the effective timespan in :attr:`effective_unit`.
        effective_unit: Unit in which the effective timespan should be represented.
        exact: True only if the backend can represent both the duration and the sliding-window
            semantics exactly.
        verified: True if the backend declared capabilities and the check was actually performed.
            False means the backend is legacy and the timespan was accepted without verification.
        precision_exact: True if the effective duration equals the requested duration.
        semantics_exact: True if the backend's window mode matches the sliding-window reference
            semantics.
        deviation_seconds: Effective duration minus requested duration. Positive values mean the
            generated query uses a wider window than requested.
        explanation: Human-readable explanation of a non-exact representation, or None for an
            exact representation.
        marker: Retention marker for approximations. ``None`` for exact representations.
    """

    requested: SigmaCorrelationTimespan
    capability: SigmaCorrelationTimespanCapability
    window_mode: SigmaCorrelationWindowMode | None
    effective_seconds: int
    effective_count: int
    effective_unit: str
    exact: bool
    precision_exact: bool
    semantics_exact: bool
    deviation_seconds: int
    explanation: str | None = None
    marker: str | None = None
    verified: bool = True

    @property
    def approximated(self: Self) -> bool:
        """Return True if the backend cannot represent the requested semantics exactly."""
        return not self.exact

    @property
    def effective_spec(self: Self) -> str:
        """Return the effective timespan in Sigma notation."""
        return f"{self.effective_count}{self.effective_unit}"

    def to_dict(self: Self) -> dict[str, Any]:
        """Return a serializable representation suitable for conversion state metadata."""
        return {
            "requested": self.requested.spec,
            "requested_seconds": self.requested.seconds,
            "min_unit": self.capability.min_unit,
            "window_mode": str(self.window_mode) if self.window_mode is not None else None,
            "effective_spec": self.effective_spec,
            "effective_seconds": self.effective_seconds,
            "exact": self.exact,
            "verified": self.verified,
            "precision_exact": self.precision_exact,
            "semantics_exact": self.semantics_exact,
            "approximated": self.approximated,
            "deviation_seconds": self.deviation_seconds,
            "explanation": self.explanation,
            "marker": self.marker,
        }


@dataclass
class SigmaCorrelationFieldAlias:
    """
    The Sigma rules used in a correlation rule possibly match events that use different field names
    for the same information. An alias field definition maps a field name that can be used in the
    group-by definition of a correlation rule to their respective field names in the events matched
    by the Sigma rules.
    """

    alias: str
    mapping: dict[SigmaRuleReference, str]

    def resolve_rule_references(self: Self, rule_collection: SigmaCollection) -> None:
        """
        Resolves all rule references in the mapping property to actual Sigma rules.

        Raises:
            sigma_exceptions.SigmaRuleNotFoundError: If a referenced rule cannot be found in the given rule collection.
        """
        for rule_ref in self.mapping.keys():
            rule_ref.resolve(rule_collection)


@dataclass
class SigmaCorrelationFieldAliases:
    aliases: dict[str, SigmaCorrelationFieldAlias] = field(default_factory=dict)

    def __iter__(self: Self) -> Iterator[SigmaCorrelationFieldAlias]:
        return iter(self.aliases.values())

    def __len__(self: Self) -> int:
        return len(self.aliases)

    @classmethod
    def from_dict(cls: type[Self], d: dict[str, Any]) -> Self:
        aliases = {}
        for alias, mapping in d.items():
            if not isinstance(mapping, dict):
                raise sigma_exceptions.SigmaCorrelationRuleError(
                    "Sigma correlation field alias mapping must be a dict"
                )

            aliases[alias] = SigmaCorrelationFieldAlias(
                alias=alias,
                mapping={
                    SigmaRuleReference(rule_ref): field_name
                    for rule_ref, field_name in mapping.items()
                },
            )

        return cls(aliases=aliases)

    def to_dict(self: Self) -> dict[str, dict[str, str]]:
        return {
            alias: {
                rule_ref.reference: field_name for rule_ref, field_name in alias_def.mapping.items()
            }
            for alias, alias_def in self.aliases.items()
        }

    def resolve_rule_references(self: Self, rule_collection: SigmaCollection) -> None:
        """
        Resolves all rule references in the aliases property to actual Sigma rules.

        Raises:
            sigma_exceptions.SigmaRuleNotFoundError: If a referenced rule cannot be found in the given rule collection.
        """
        for alias in self.aliases.values():
            alias.resolve_rule_references(rule_collection)


@dataclass
class SigmaCorrelationRule(SigmaRuleBase, ProcessingItemTrackingMixin):
    type: SigmaCorrelationType = SigmaCorrelationType.EVENT_COUNT
    rules: list[SigmaRuleReference] | None = None
    generate: bool = field(default=False)
    timespan: SigmaCorrelationTimespan = field(
        default_factory=lambda: SigmaCorrelationTimespan("1m")
    )
    group_by: list[str] | None = None
    aliases: SigmaCorrelationFieldAliases = field(default_factory=SigmaCorrelationFieldAliases)
    condition: SigmaCorrelationCondition | SigmaExtendedCorrelationCondition = field(
        default_factory=lambda: SigmaCorrelationCondition(SigmaCorrelationConditionOperator.GTE, 1)
    )
    referenced_rules: list[SigmaRuleReference] = field(
        default_factory=list, init=False, repr=False, compare=False
    )
    source: SigmaRuleLocation | None = field(default=None, compare=False)

    def __post_init__(self: Self) -> None:
        super().__post_init__()
        # Validate rules is not None unless extended correlation condition is defined
        if self.rules is None and not isinstance(self.condition, SigmaExtendedCorrelationCondition):
            raise sigma_exceptions.SigmaCorrelationRuleError(
                "Sigma correlation rule without rules list requires an extended correlation condition",
                source=self.source,
            )

        # Validate extended conditions are only used with temporal correlation types
        if isinstance(self.condition, SigmaExtendedCorrelationCondition) and self.type not in {
            SigmaCorrelationType.TEMPORAL,
            SigmaCorrelationType.TEMPORAL_ORDERED,
        }:
            raise sigma_exceptions.SigmaCorrelationConditionError(
                "Extended conditions can only be used with temporal or temporal_ordered correlation types",
                source=self.source,
            )

        # Validate that all rules in the rules list are referenced in extended condition
        if isinstance(self.condition, SigmaExtendedCorrelationCondition) and self.rules is not None:
            referenced_rules = set(self.condition.get_referenced_rules())

            # Get all rule references from the rules list
            defined_rules = {rule.reference for rule in self.rules}

            # Check if all defined rules are referenced in the condition
            unreferenced_rules = defined_rules - referenced_rules
            if unreferenced_rules:
                raise sigma_exceptions.SigmaCorrelationConditionError(
                    f"Rules defined but not referenced in extended condition: {', '.join(sorted(unreferenced_rules))}",
                    source=self.source,
                )
            # Check if all rules referenced in the condition are defined in the rules list
            undefined_rules = referenced_rules - defined_rules
            if undefined_rules:
                raise sigma_exceptions.SigmaCorrelationConditionError(
                    f"Rules referenced in extended condition but not defined in rules list: {', '.join(sorted(undefined_rules))}",
                    source=self.source,
                )

        if self.type not in {
            SigmaCorrelationType.TEMPORAL,
            SigmaCorrelationType.TEMPORAL_ORDERED,
        } and not isinstance(self.condition, SigmaCorrelationCondition):
            raise sigma_exceptions.SigmaCorrelationRuleError(
                "Non-temporal Sigma correlation rule without condition", source=self.source
            )
        if (
            self.type
            in {
                SigmaCorrelationType.VALUE_COUNT,
                SigmaCorrelationType.VALUE_SUM,
                SigmaCorrelationType.VALUE_AVG,
                SigmaCorrelationType.VALUE_PERCENTILE,
                SigmaCorrelationType.VALUE_MEDIAN,
            }
            and isinstance(self.condition, SigmaCorrelationCondition)
            and self.condition.fieldref is None
        ):
            # Format type name for error message (special case for VALUE_COUNT to match existing tests)
            if self.type == SigmaCorrelationType.VALUE_COUNT:
                type_name = "Value count"
            else:
                type_name = self.type.name.replace("_", " ").capitalize()
            raise sigma_exceptions.SigmaCorrelationRuleError(
                f"{type_name} correlation rule without field reference",
                source=self.source,
            )

    @classmethod
    def from_dict(  # type: ignore[override]
        cls,
        rule: dict[str, Any],
        collect_errors: bool = False,
        source: SigmaRuleLocation | None = None,
        policy: "SigmaPolicy | None" = None,
    ) -> Self:
        kwargs, errors = super().from_dict_common_params(
            rule, collect_errors, source, policy=policy
        )
        correlation_rule: Any = rule.get("correlation", dict())
        if not isinstance(correlation_rule, dict):
            errors.append(
                sigma_exceptions.SigmaCorrelationRuleError(
                    "Sigma correlation rule 'correlation' field must be a dict", source=source
                )
            )
            if not collect_errors:
                raise errors[0]
            correlation_rule = dict()

        # Correlation type
        correlation_type = correlation_rule.get("type")
        if correlation_type is not None:
            try:
                correlation_type = SigmaCorrelationType[correlation_type.upper()]
            except KeyError:
                errors.append(
                    sigma_exceptions.SigmaCorrelationTypeError(
                        f"'{ correlation_type }' is no valid Sigma correlation type", source=source
                    )
                )
        else:  # no correlation type provided
            errors.append(
                sigma_exceptions.SigmaCorrelationTypeError(
                    "Sigma correlation rule without type", source=source
                )
            )

        # Rules
        rules_value = correlation_rule.get("rules")
        rules: list[SigmaRuleReference] | None = []  # Initialize to empty list
        if rules_value is not None:
            if isinstance(rules_value, str):
                # Simple rule reference
                rules = [SigmaRuleReference(rules_value)]
            elif isinstance(rules_value, list):
                rules = [SigmaRuleReference(rule) for rule in rules_value]
            else:
                errors.append(
                    sigma_exceptions.SigmaCorrelationRuleError(
                        "Rule reference must be plain string or list.", source=source
                    )
                )
        elif correlation_type not in (
            SigmaCorrelationType.TEMPORAL,
            SigmaCorrelationType.TEMPORAL_ORDERED,
        ):
            # Only require rules for non-temporal types (temporal types can extract from condition)
            errors.append(
                sigma_exceptions.SigmaCorrelationRuleError(
                    "Sigma correlation rule without rule references", source=source
                )
            )

        # Generate
        generate = correlation_rule.get("generate")
        if generate is not None:
            if not isinstance(generate, bool):
                errors.append(
                    sigma_exceptions.SigmaCorrelationRuleError(
                        "Sigma correlation generate definition must be a boolean", source=source
                    )
                )
        else:
            generate = False

        # Group by
        group_by = correlation_rule.get("group-by")
        if group_by is not None:
            if isinstance(group_by, str):
                group_by = [group_by]
            if isinstance(group_by, list):
                group_by = [str(group) for group in group_by]
            else:
                errors.append(
                    sigma_exceptions.SigmaCorrelationRuleError(
                        "Sigma correlation group-by definition must be string or list",
                        source=source,
                    )
                )

        # Time span
        timespan = correlation_rule.get("timespan")
        if timespan is not None:
            try:
                timespan = SigmaCorrelationTimespan(timespan)
            except SigmaTimespanError as e:
                errors.append(e)
        else:
            errors.append(
                sigma_exceptions.SigmaCorrelationRuleError(
                    "Sigma correlation rule without timespan", source=source
                )
            )

        # Aliases
        aliases = correlation_rule.get("aliases")
        if aliases is not None:
            if isinstance(aliases, dict):
                aliases = SigmaCorrelationFieldAliases.from_dict(aliases)
            else:
                errors.append(
                    sigma_exceptions.SigmaCorrelationRuleError(
                        "Sigma correlation aliases definition must be a dict", source=source
                    )
                )
        else:
            aliases = SigmaCorrelationFieldAliases()

        # Condition - can be either a dict (basic condition) or a string (extended condition)
        condition_value = correlation_rule.get("condition")
        condition: SigmaCorrelationCondition | SigmaExtendedCorrelationCondition = (
            SigmaCorrelationCondition(SigmaCorrelationConditionOperator.GTE, 1)
        )

        if condition_value is not None:
            if isinstance(condition_value, dict):
                # Basic condition
                condition = SigmaCorrelationCondition.from_dict(condition_value, source=source)
            elif isinstance(condition_value, str):
                # Extended condition - only valid for temporal types
                if correlation_type not in (
                    SigmaCorrelationType.TEMPORAL,
                    SigmaCorrelationType.TEMPORAL_ORDERED,
                ):
                    errors.append(
                        sigma_exceptions.SigmaCorrelationRuleError(
                            "Extended conditions (string) can only be used with temporal or temporal_ordered correlation types",
                            source=source,
                        )
                    )
                else:
                    # Extended condition - parse as SigmaExtendedCorrelationCondition
                    try:
                        condition = SigmaExtendedCorrelationCondition(
                            condition_value, source=source
                        )
                    except sigma_exceptions.SigmaCorrelationConditionError as e:
                        errors.append(e)
            else:
                errors.append(
                    sigma_exceptions.SigmaCorrelationRuleError(
                        "Sigma correlation condition definition must be a dict or string",
                        source=source,
                    )
                )
        elif correlation_type not in (
            SigmaCorrelationType.TEMPORAL,
            SigmaCorrelationType.TEMPORAL_ORDERED,
        ):
            errors.append(
                sigma_exceptions.SigmaCorrelationRuleError(
                    "Non-temporal Sigma correlation rule without condition", source=source
                )
            )
        elif correlation_type in (
            SigmaCorrelationType.TEMPORAL,
            SigmaCorrelationType.TEMPORAL_ORDERED,
        ):
            # For temporal types without condition, set default
            # default condition for temporal correlation rules: count >= number of rules
            rules_count = len(rules) if rules is not None else 0
            condition = SigmaCorrelationCondition(
                op=SigmaCorrelationConditionOperator.GTE, count=rules_count, source=source
            )

        if not collect_errors and errors:
            raise errors[0]

        # Convert empty rules list to None if using extended condition
        if (
            rules is not None
            and not rules
            and isinstance(condition, SigmaExtendedCorrelationCondition)
        ):
            rules = None

        return cls(
            type=correlation_type,
            rules=rules,
            generate=generate,
            timespan=timespan,
            group_by=group_by,
            aliases=aliases,
            condition=condition,
            errors=errors,
            **kwargs,
        )

    @classmethod
    def from_yaml(
        cls, rule: str, collect_errors: bool = False, policy: "SigmaPolicy | None" = None
    ) -> Self:
        """Convert YAML input string with single document into SigmaCorrelationRule object."""
        return super().from_yaml(rule, collect_errors, policy=policy)

    def to_dict(self: Self) -> dict[str, Any]:
        d = super().to_dict()
        dc = {
            "type": self.type.name.lower(),
            "rules": [rule.reference for rule in self.rules] if self.rules is not None else [],
            "timespan": self.timespan.spec,
            "group-by": self.group_by,
            "aliases": self.aliases.to_dict() if self.aliases is not None else None,
        }

        # Serialize condition based on its type
        if self.condition is not None:
            dc["condition"] = self.condition.to_dict()

        d["correlation"] = dc

        return d

    def resolve_rule_references(self: Self, rule_collection: SigmaCollection) -> None:
        """
        Resolves all rule references in the rules property to actual Sigma rules.
        If rules is None and an extended condition is defined, extracts rule references
        from the condition. Populates the referenced_rules list with resolved references.

        Raises:
            sigma_exceptions.SigmaRuleNotFoundError: If a referenced rule cannot be found in the given rule collection.
        """
        # Determine which rules to use: explicit rules or extracted from extended condition
        if self.rules is not None:
            self.referenced_rules = self.rules
        elif isinstance(self.condition, SigmaExtendedCorrelationCondition):
            referenced_rule_names = self.condition.get_referenced_rules()
            self.referenced_rules = [SigmaRuleReference(name) for name in referenced_rule_names]
        else:
            self.referenced_rules = []

        # Resolve all rule references
        for rule_ref in self.referenced_rules:
            rule_ref.resolve(rule_collection)
            rule = rule_ref.rule
            rule.add_backreference(self)
            if not self.generate:
                rule.disable_output()

    def flatten_rules(
        self: Self, include_correlations: bool = True
    ) -> list[SigmaRule | SigmaCorrelationRule]:
        """
        Flattens the rules in the correlation rule and returns a list of Sigma rules. If include_correlations
        is set to False, only the Sigma rules are returned, excluding nested correlation rules.

        Returns:
            List of Sigma rules.
        """
        rules: list[SigmaRule | SigmaCorrelationRule] = []
        for rule_ref in self.referenced_rules:
            rule = rule_ref.rule
            if isinstance(rule, SigmaCorrelationRule):
                if include_correlations:
                    rules.append(rule)
                rules.extend(rule.flatten_rules())
            else:
                rules.append(rule)
        return rules
