from __future__ import annotations

import copy
import random
import re
import string
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from typing import Self

from sigma import exceptions as sigma_exceptions
from sigma.correlations import SigmaCorrelationRule, SigmaRuleReference
from sigma.rule import SigmaDetection, SigmaDetections, SigmaLogSource, SigmaRule, SigmaRuleBase
from sigma.rule.logsource import EmptyLogSource
from sigma.suppression import RULES_ANY, SuppressionSource

if TYPE_CHECKING:
    from sigma.exceptions import SigmaRuleLocation
    from sigma.policy import SigmaPolicy


@dataclass
class SigmaGlobalFilter(SigmaDetections):
    rules: list[SigmaRuleReference] | str = field(default_factory=list)

    @classmethod
    def from_dict(
        cls: type[Self],
        detections: dict[str, Any],
        source: SigmaRuleLocation | None = None,
        policy: "SigmaPolicy | None" = None,
    ) -> Self:
        try:
            if isinstance(detections["condition"], str):
                condition = [detections["condition"]]
            else:
                raise sigma_exceptions.SigmaFilterConditionError(
                    "Sigma filter condition must be a string", source=source
                )
        except KeyError:
            raise sigma_exceptions.SigmaFilterConditionError(
                "Sigma filter must contain exactly one condition", source=source
            )

        try:
            rules: list[SigmaRuleReference] | str
            if isinstance(detections["rules"], str):
                # Check if it's "any" keyword
                if detections["rules"].lower() == "any":
                    rules = detections["rules"].lower()
                else:
                    # Single rule reference
                    rules = [SigmaRuleReference(detections["rules"])]
            elif isinstance(detections["rules"], list):
                # Empty list is treated as "any"
                if not detections["rules"]:
                    rules = "any"
                else:
                    rules = [SigmaRuleReference(detection) for detection in detections["rules"]]
            else:
                raise sigma_exceptions.SigmaFilterRuleReferenceError(
                    "Sigma filter rules field must be 'any', a rule ID/name, or a list of rule IDs/names",
                    source=source,
                )
        except KeyError:
            # Rules field is required - must explicitly specify "any" or specific rule references
            raise sigma_exceptions.SigmaFilterRuleReferenceError(
                "Sigma filter must have a 'rules' field (use 'any' to apply to all rules matching the logsource)",
                source=source,
            )

        return cls(
            detections={
                name: SigmaDetection.from_definition(definition, source, policy)
                for name, definition in detections.items()
                if name
                not in (
                    "condition",
                    "rules",
                )  # TODO Fix standard
            },
            rules=rules,
            condition=condition,
            source=source,
            policy=policy,
        )

    def to_dict(self: Self) -> dict[str, Any]:
        d = super().to_dict()
        d.update(
            {
                "rules": (
                    self.rules
                    if isinstance(self.rules, str)
                    else [ref.reference for ref in self.rules]
                ),
            }
        )

        return d


@dataclass
class EmptySigmaGlobalFilter(SigmaGlobalFilter):
    """
    Empty Sigma global filter used as a placeholder for error handling purposes.
    """

    detections: dict[str, SigmaDetection] = field(default_factory=dict)
    condition: list[str] = field(default_factory=list)
    rules: list[SigmaRuleReference] | str = field(default_factory=list)

    def __post_init__(self: Self) -> None:
        # Skip all checks and initializations
        pass


@dataclass
class SigmaFilter(SigmaRuleBase):
    """
    SigmaFilter class is used to represent a Sigma filter object.
    """

    logsource: SigmaLogSource = field(default_factory=SigmaLogSource)
    filter: SigmaGlobalFilter = field(
        default_factory=lambda: SigmaGlobalFilter({}, []),
    )

    @classmethod
    def from_dict(  # type: ignore[override]
        cls: type[Self],
        sigma_filter: dict[str, Any],
        collect_errors: bool = False,
        source: SigmaRuleLocation | None = None,
        policy: "SigmaPolicy | None" = None,
    ) -> Self:
        """
        Converts from a dictionary object to a SigmaFilter object.
        """
        kwargs, errors = super().from_dict_common_params(
            sigma_filter, collect_errors, source, policy=policy
        )

        # parse log source
        try:
            filter_logsource = SigmaLogSource.from_dict(sigma_filter["logsource"], source)
        except KeyError:
            filter_logsource = EmptyLogSource()
            errors.append(
                sigma_exceptions.SigmaLogsourceError(
                    "Sigma filter must have a log source", source=source
                )
            )
        except AttributeError:
            filter_logsource = EmptyLogSource()
            errors.append(
                sigma_exceptions.SigmaLogsourceError(
                    "Sigma logsource must be a valid YAML map", source=source
                )
            )
        except sigma_exceptions.SigmaError as e:
            filter_logsource = EmptyLogSource()
            errors.append(e)

        # parse detections
        try:
            filter_global_filter = SigmaGlobalFilter.from_dict(
                sigma_filter["filter"], source, policy=policy
            )
        except KeyError:
            filter_global_filter = EmptySigmaGlobalFilter()
            errors.append(
                sigma_exceptions.SigmaFilterError(
                    "Sigma filter must have a filter defined", source=source
                )
            )
        except TypeError:
            filter_global_filter = EmptySigmaGlobalFilter()
            errors.append(
                sigma_exceptions.SigmaFilterError(
                    "Sigma filter must be a dictionary", source=source
                )
            )
        except sigma_exceptions.SigmaError as e:
            filter_global_filter = EmptySigmaGlobalFilter()
            errors.append(e)

        if not collect_errors and errors:
            raise errors[0]

        return cls(
            logsource=filter_logsource,
            filter=filter_global_filter,
            errors=errors,
            **kwargs,
        )

    def to_dict(self: Self) -> dict[str, Any]:
        """Convert filter object into dict."""
        d = super().to_dict()
        d.update(
            {
                "logsource": self.logsource.to_dict(),
                "filter": self.filter.to_dict(),
            }
        )

        return d

    def _matched_rule_references(
        self: Self, rule: SigmaRule | SigmaCorrelationRule
    ) -> list[str] | str | None:
        """Return the filter rule references that match *rule*.

        Returns:
            * :data:`sigma.suppression.RULES_ANY` when the filter applies to all
              rules matching the logsource (``rules: any``),
            * the list of concrete references (rule IDs or names) that resolve to
              *rule*,
            * ``None`` when the filter does not apply to *rule*.

        Correlation rules are never filtered.
        """
        from sigma.collection import SigmaCollection

        # Don't apply filters to correlation rules
        if isinstance(rule, SigmaCorrelationRule):
            return None

        # Check if logsource matches
        if rule.logsource not in self.logsource:
            return None

        # If rules is "any", apply to all rules matching the logsource
        if isinstance(self.filter.rules, str) and self.filter.rules.lower() == "any":
            return RULES_ANY

        # At this point, rules must be a list (not a string)
        assert isinstance(self.filter.rules, list)

        # For each rule ID/title in the filter.rules, add the rule to the reference using the resolve method,
        # then filter each reference to see if the rule is in the reference
        matches: list[str] = []
        for reference in self.filter.rules:
            try:
                SigmaCollection([rule])[reference.reference]
            except sigma_exceptions.SigmaRuleNotFoundError:
                continue
            matches.append(reference.reference)

        if not matches:
            return None

        return matches

    def _should_apply_on_rule(self: Self, rule: SigmaRule | SigmaCorrelationRule) -> bool:
        return self._matched_rule_references(rule) is not None

    # Keywords that must not be prefixed when rewriting filter conditions. They are compared
    # case-sensitively, like in the condition grammar in sigma.conditions, where e.g. "NOT" is
    # an ordinary identifier and not the negation operator.
    _CONDITION_KEYWORDS: frozenset[str] = frozenset({"not", "and", "or", "all", "any", "of", "1"})

    # A single condition token: a detection identifier or an identifier pattern. Mirrors the
    # character sets of ``identifier`` (alphanumerics, ``_`` and ``-``) and ``identifier_pattern``
    # (the same characters plus ``*``) in sigma.conditions. Identifiers may start with any of
    # these characters, e.g. ``_filter`` or ``2nd_filter``.
    _CONDITION_TOKEN: ClassVar[re.Pattern[str]] = re.compile(r"[a-zA-Z0-9_*-]+")

    def apply_on_rule(
        self: Self, rule: SigmaRule | SigmaCorrelationRule
    ) -> SigmaRule | SigmaCorrelationRule:
        matched_references = self._matched_rule_references(rule)
        if matched_references is None or isinstance(rule, SigmaCorrelationRule):
            return rule

        # Generate one random prefix shared by all filter identifiers in this application.
        # Using a single prefix (rather than a fresh random name per identifier) preserves
        # the structure of the original identifier names so that wildcard patterns in the
        # filter condition (e.g. "1 of selection_*") continue to work after renaming.
        prefix = "_filt_" + "".join(random.choices(string.ascii_lowercase, k=10))

        # Provenance follows the actual filter condition nodes: one source is recorded
        # per filter application and attached to every copied filter detection, which lets
        # the suppression module recover it from the leaves of the final condition tree.
        # Filters that did not match never reach this point and therefore leave no source.
        suppression_source = SuppressionSource(
            filter_title=self.title,
            filter_id=str(self.id) if self.id is not None else None,
            filter_name=self.name,
            matched_rules=matched_references,
            filter_condition=self.filter.condition[0],
            prefix=prefix,
            filter_source=self.source,
            rule_source=rule.source,
            rule_title=rule.title,
            rule_id=str(rule.id) if rule.id is not None else None,
        )
        rule.detection.suppression_sources[prefix] = suppression_source

        # Rename every filter detection identifier with the shared prefix. Each rule gets its own
        # copy of the filter detections: processing pipelines modify detections in place, so a
        # detection object shared between rules would be transformed again for every rule.
        for original_cond_name, condition in self.filter.detections.items():
            copied_condition = copy.deepcopy(condition)
            self._attach_suppression(copied_condition, suppression_source)
            rule.detection.detections[prefix + "_" + original_cond_name] = copied_condition

        # Rewrite the filter condition string so that every identifier/pattern token is
        # prefixed.  This handles:
        #   - exact names:        "selection"    -> "PREFIX_selection"
        #   - suffix wildcards:   "selection_*"  -> "PREFIX_selection_*"
        #   - prefix wildcards:   "*_allow"      -> "PREFIX_*_allow"
        #   - the "them" keyword: "1 of them"    -> "1 of PREFIX_*"
        #   - leading "_"/digits: "_filter"      -> "PREFIX__filter"
        # Sigma keywords (not, and, or, all, any, of, 1) are left unchanged.
        #
        # Each token is a maximal run of the characters allowed in Sigma identifiers and
        # identifier patterns (see _CONDITION_TOKEN). Wildcards are only valid at the start or
        # end of a Sigma identifier pattern but the regex accepts any occurrence; the Sigma
        # condition parser is responsible for rejecting syntactically invalid patterns at parse
        # time.
        def _replace_token(m: re.Match[str]) -> str:
            token = m.group(0)
            if token in self._CONDITION_KEYWORDS:
                return token
            if token == "them":
                # "them" means all detections; replace with a pattern that matches all
                # filter identifiers carrying the current prefix.
                return prefix + "_*"
            return prefix + "_" + token

        filter_condition = self._CONDITION_TOKEN.sub(_replace_token, self.filter.condition[0])

        for i, condition_str in enumerate(rule.detection.condition):
            rule.detection.condition[i] = f"({condition_str}) and " + f"({filter_condition})"

        # Reparse the rule to update the parsed conditions
        rule.detection.__post_init__()

        return rule

    @staticmethod
    def _attach_suppression(
        detection: SigmaDetection, suppression_source: SuppressionSource
    ) -> None:
        """Attach the suppression source to a copied filter detection and its nested copies."""
        detection.suppression = suppression_source
        for item in detection.detection_items:
            if isinstance(item, SigmaDetection):
                SigmaFilter._attach_suppression(item, suppression_source)

    @classmethod
    def from_yaml(
        cls: type[Self],
        rule: str,
        collect_errors: bool = False,
        policy: "SigmaPolicy | None" = None,
    ) -> Self:
        """Convert YAML input string with single document into SigmaFilter object."""
        return super().from_yaml(rule, collect_errors, policy=policy)
