#!/usr/bin/env python3
"""
Demonstrates the conservative offline Sigma rule comparison on three typical
rule updates plus one rule that is deliberately outside the supported fragment.

Run from the repository root:

    python examples/rule_comparison/demo.py
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from sigma.compare import compare_rules, event_matches_rule
from sigma.processing.pipeline import ProcessingPipeline

HERE = pathlib.Path(__file__).parent


def load(name: str) -> str:
    return (HERE / name).read_text()


def show(title: str, result, old_yaml: str, new_yaml: str, pipeline=None) -> None:
    print(f"=== {title} ===")
    print(f"relation: {result.relation.value}")
    print(f"reason:   {result.reason}")
    if result.metadata_changes:
        print("metadata changes:")
        for change in result.metadata_changes:
            print(f"  - {change.field}: {change.old!r} -> {change.new!r}")
    if result.unsupported:
        print(f"unsupported: {result.unsupported}")
    if result.distinguishing_event is not None:
        event = result.distinguishing_event
        print(f"distinguishing event: {event}")
        # Independent re-verification of the evidence:
        matches_old = event_matches_rule(old_yaml, event, pipeline)
        matches_new = event_matches_rule(new_yaml, event, pipeline)
        print(f"re-verified: matches old={matches_old}, matches new={matches_new}")
    print()


def main() -> None:
    pipeline = ProcessingPipeline.from_yaml(load("pipeline.yml"))

    v1 = load("suspicious_process_v1.yml")
    v2_added = load("suspicious_process_v2_added_value.yml")
    v2_tight = load("suspicious_process_v2_tightened.yml")
    v2_desc = load("suspicious_process_v2_description.yml")
    complex_v1 = load("complex_rule_v1.yml")
    complex_v2 = load("complex_rule_v2.yml")

    show(
        "1. New suspicious value added (pwsh.exe), compared after field mapping",
        compare_rules(v1, v2_added, pipeline),
        v1,
        v2_added,
        pipeline,
    )
    show(
        "2. Condition tightened (extra AND on ParentImage)",
        compare_rules(v1, v2_tight, pipeline),
        v1,
        v2_tight,
        pipeline,
    )
    show(
        "3. Description/metadata only",
        compare_rules(v1, v2_desc, pipeline),
        v1,
        v2_desc,
        pipeline,
    )
    show(
        "4. Complex rule (regex, endswith, NOT) - must stay unknown",
        compare_rules(complex_v1, complex_v2, pipeline),
        complex_v1,
        complex_v2,
        pipeline,
    )


if __name__ == "__main__":
    main()
