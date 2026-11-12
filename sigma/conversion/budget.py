"""Conversion-wide complexity budget.

Sigma content accepted from external sources can be small in terms of bytes while still
expanding into a huge query tree inside the conversion pipeline. The three expansion
mechanisms responsible for this are:

1. condition selectors (``1 of selection_*`` / ``all of them``) which fan a single token
   out into one condition node per matched detection identifier,
2. value modifiers (e.g. ``base64offset``, ``windash``) which replace one value with a
   :class:`~sigma.types.SigmaExpansion` containing several candidate values, and
3. field name mappings that map one field onto many target fields, producing one detection
   item (and later one query subexpression) per target field.

This module provides a single budget object that is shared by all stages of one conversion
run. It counts the *actual* expanded intermediate nodes/candidates as they are produced - it
never expands everything first and measures the result afterwards, and it does not rely on
wall-clock timeouts. A large but linear rule therefore consumes budget proportional to its
size, whereas combinatorial growth aborts as soon as the limit is crossed.
"""

from __future__ import annotations

import contextvars
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sigma.exceptions import SigmaComplexityBudgetExceededError

if TYPE_CHECKING:
    from sigma.rule import SigmaRuleBase

#: Stages at which budget can be consumed. Kept as constants so error messages stay stable.
STAGE_CONDITION_SELECTOR = "condition-selector"
STAGE_MODIFIER_EXPANSION = "modifier-expansion"
STAGE_FIELD_MAPPING = "field-mapping"

#: Holds the budget of the currently running conversion (if any). Allows the low level
#: expansion code in conditions, modifiers and processing transformations to charge against
#: the budget without threading an explicit parameter through every constructor.
_current_budget: contextvars.ContextVar[ComplexityBudget | None] = contextvars.ContextVar(
    "sigma_complexity_budget", default=None
)


@dataclass
class BudgetCharge:
    """A single budget consumption event, used for diagnostics."""

    amount: int
    stage: str
    rule: str | None
    processing_item: str | None


@dataclass
class ComplexityBudget:
    """
    Shared complexity budget for one conversion run.

    The same instance is used while the processing pipeline is applied and while the
    condition tree is converted, so that the costs of selector expansion, modifier expansion
    and one-to-many field mappings accumulate together. It can be bound in two ways:

    * as the active budget of a context via :func:`activate_budget`, which covers pipeline
      application and condition conversion (both happen inside ``Backend.convert``);
    * directly on a rule under construction via :meth:`guard_parsing`, which additionally
      covers value modifier expansion, because modifiers run while the Sigma YAML is parsed,
      before the backend conversion starts.

    Only budgeted expansion work is charged; ordinary linear rule content (one charge per
    real intermediate node/candidate) grows the counter linearly, while combinatorial
    expansion crosses the limit early and raises
    :class:`~sigma.exceptions.SigmaComplexityBudgetExceededError`.
    """

    limit: int
    rule: SigmaRuleBase | None = field(default=None, compare=False)
    rule_label: str | None = field(default=None, compare=False)
    processing_item: str | None = field(default=None, compare=False)
    consumed: int = field(default=0, init=False)
    charges: list[BudgetCharge] = field(default_factory=list, init=False, repr=False)
    _instance_token: contextvars.Token | None = field(
        default=None, init=False, repr=False, compare=False
    )

    def begin_rule(self, rule: SigmaRuleBase | None) -> None:
        """Bind the budget to the rule that is currently being converted."""
        self.rule = rule
        if rule is not None:
            self.rule_label = str(
                getattr(rule, "id", None) or getattr(rule, "title", None) or rule
            )
        self.processing_item = None

    def begin_rule_label(self, label: str | None) -> None:
        """
        Bind the budget to a rule identified by a plain label.

        Used while a rule is still being parsed and the SigmaRule instance is not available
        yet, but the title/name/id from the raw YAML already is.
        """
        self.rule_label = str(label) if label is not None else None
        self.processing_item = None

    def begin_processing_item(self, identifier: str | None) -> None:
        """Bind the budget to the processing item currently applied to the rule."""
        self.processing_item = identifier

    def end_processing_item(self) -> None:
        """Leave the scope of a processing item."""
        self.processing_item = None

    def guard_parsing(self) -> "ComplexityBudget":
        """
        Activate this budget as the context budget so that modifier expansion performed while
        a rule is parsed is charged against it.

        Returns the budget itself, allowing ``with ComplexityBudget(...).guard_parsing():``.
        Use :meth:`close_guard` (or the context-manager protocol) to deactivate it. A budget
        must only be guarded once.
        """
        if self._instance_token is not None:
            raise RuntimeError("Complexity budget is already activated as a parsing guard.")
        self._instance_token = _current_budget.set(self)
        return self

    def close_guard(self) -> None:
        """Deactivate a budget previously activated with :meth:`guard_parsing`."""
        if self._instance_token is not None:
            _current_budget.reset(self._instance_token)
            self._instance_token = None

    def __enter__(self) -> "ComplexityBudget":
        return self.guard_parsing()

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close_guard()

    def _rule_label(self) -> str | None:
        if self.rule_label is not None:
            return self.rule_label
        if self.rule is None:
            return None
        return str(getattr(self.rule, "id", None) or getattr(self.rule, "title", None) or self.rule)

    def charge(self, amount: int, stage: str) -> None:
        """
        Account ``amount`` newly produced intermediate nodes/candidates against the budget.

        The charge is applied incrementally while the expansion is being built, therefore an
        over-limit expansion aborts at the moment it crosses the limit instead of being fully
        materialized first.
        """
        if amount <= 0:
            return
        self.consumed += amount
        self.charges.append(
            BudgetCharge(amount, stage, self._rule_label(), self.processing_item)
        )
        if self.consumed > self.limit:
            raise SigmaComplexityBudgetExceededError(
                f"Conversion complexity budget of {self.limit} exceeded "
                f"(consumed {self.consumed}) during {stage}; "
                f"rule={self._rule_label()}, processing_item={self.processing_item}",
                source=getattr(self.rule, "source", None),
                rule=self._rule_label(),
                processing_item=self.processing_item,
                stage=stage,
                limit=self.limit,
                consumed=self.consumed,
            )


def current_budget() -> ComplexityBudget | None:
    """Return the budget of the running conversion, or None when no budget is active."""
    return _current_budget.get()


def charge_budget(amount: int, stage: str) -> None:
    """
    Charge expansion work against the active budget, if one exists.

    Calls outside of a budgeted conversion (e.g. standalone rule parsing in tests) are
    no-ops, so the expansion hooks are safe to keep unconditionally.
    """
    budget = _current_budget.get()
    if budget is not None:
        budget.charge(amount, stage)


def activate_budget(budget: ComplexityBudget) -> contextvars.Token:
    """Make ``budget`` the active budget for the current context."""
    return _current_budget.set(budget)


def deactivate_budget(token: contextvars.Token) -> None:
    """Restore the previously active budget (usually None)."""
    _current_budget.reset(token)
