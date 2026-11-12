# Conservative Sigma Rule Comparison (offline)

`sigma/compare.py` answers one review question: does a rule update **expand**,
**narrow**, or **keep** the set of events it alerts on? Both rule versions are
processed by the *same* processing pipeline (field mappings are applied before
comparison), and the result is one of:

- `equivalent` – detection logic provably matches the same events; metadata
  changes (description, modified date, ...) are listed separately.
- `expands` / `narrows` – proven by a *distinguishing event*: a concrete
  field/value assignment that matches one version but not the other. The event
  is re-verified by evaluation and can be checked independently with
  `sigma.compare.event_matches_rule`.
- `unknown` – no relation could be proven. This is the answer whenever the
  rules use constructs outside the supported fragment: regular expressions,
  wildcards, value modifiers (`contains`, `endswith`, `all`, ...), keyword
  detections, `not` in conditions, patterned selectors (`1 of selection_*`),
  correlation rules, or differing log sources. Nothing is guessed and no
  online service or model is consulted.

Supported semantics: plain string equality (`field: value`), OR-linked value
lists (set inclusion), and `and`/`or` condition combinations including
`1 of them` / `all of them`.

## Scenarios in this directory

- `suspicious_process_v1.yml` → `suspicious_process_v2_added_value.yml`:
  a new suspicious value (`pwsh.exe`) is added → **expands**, with
  distinguishing event `{"ProcessName": "pwsh.exe"}` (field name after the
  mapping in `pipeline.yml`).
- `suspicious_process_v1.yml` → `suspicious_process_v2_tightened.yml`:
  the condition is tightened with an extra `AND` → **narrows**, with a
  distinguishing event that matches the old rule only.
- `suspicious_process_v1.yml` → `suspicious_process_v2_description.yml`:
  description/metadata only → **equivalent**, metadata changes listed.
- `complex_rule_v1.yml` → `complex_rule_v2.yml`: regex, `endswith` and `not`
  are involved → **unknown** (unsupported constructs are never forced into a
  verdict).

## Usage

```bash
# demo of all four scenarios
python examples/rule_comparison/demo.py

# CLI: compare two rule files under a shared pipeline, JSON output
python -m sigma.compare old.yml new.yml --pipeline pipeline.yml
```

Library API: `sigma.compare.compare_rules(old, new, pipeline=None)` returns a
`ComparisonResult`; `sigma.compare.event_matches_rule(rule, event, pipeline)`
re-verifies a distinguishing event against a single rule version.
