"""
End-to-end demonstration of the strengthened correlation field alias / group-by checks.

Run with:

    python tests/demo_correlation_alias_groupby.py

Scenario: two log sources use different field names for the user entity
(``user.name`` vs. ``subject``). A correlation rule must declare an explicit field
alias so that the two names are treated as the same entity. The demo shows:

1. With the explicit alias the generated query normalizes both source fields into the
   shared key and keeps same-named users on different hosts in separate groups.
2. Deleting one alias mapping makes the correlation key unrepresentable: conversion is
   rejected with an error that names the concrete source rule and correlation key
   instead of emitting a broad query that merges the two hosts' security events.
3. Relying on a plain group-by field that is missing in a source rule is rejected.
4. A backend that cannot emit field normalization expressions rejects aliases.
5. A pipeline that fans one source field out into several fields is rejected.
"""

from sigma.backends.test.backend import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaCorrelationFieldError
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation


RULES = """
title: Host A security logon
name: host_a_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
fields:
    - host.name
    - user.name
---
title: Host B security logon
name: host_b_logon
status: test
logsource:
    product: linux
    service: auth
detection:
    selection:
        EventID: 4624
    condition: selection
fields:
    - host.name
    - subject
"""


def correlation_yaml(aliases: str | None, group_by: list[str]) -> str:
    alias_block = f"    aliases:\n{aliases}\n" if aliases else ""
    group_block = "\n".join(f"        - {key}" for key in group_by)
    return f"""
{RULES}
---
title: Cross-host user correlation
status: test
correlation:
    type: event_count
    rules:
        - host_a_logon
        - host_b_logon
    timespan: 5m
{alias_block}    group-by:
{group_block}
    condition:
        gte: 2
"""


def heading(text: str) -> None:
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def main() -> None:
    backend = TextQueryTestBackend()

    heading("1. Explicit alias: same-named users stay grouped per host, not merged")
    # Two event streams share the username "alice" but live on different hosts:
    #   host-a: {"host.name": "host-a", "user.name": "alice", ...}
    #   host-b: {"host.name": "host-b", "subject": "alice", ...}
    # The alias maps each source-specific user field to one shared correlation key, while
    # host.name keeps host-a and host-b events in separate aggregation groups even though
    # both usernames are identical.
    with_alias = correlation_yaml(
        aliases=(
            "        user:\n"
            "            host_a_logon: user.name\n"
            "            host_b_logon: subject\n"
        ),
        group_by=["host.name", "user"],
    )
    query = backend.convert(SigmaCollection.from_yaml(with_alias))[0]
    print(query)
    assert "set user='user.name'" in query
    assert "set user=subject" in query
    # Grouping by host first prevents merging the two hosts' security events; the user
    # alias merges only the differing names of the same entity within a host.
    assert " by 'host.name', user" in query

    heading("2. Delete one alias mapping: conversion is rejected")
    incomplete_alias = correlation_yaml(
        aliases="        user:\n            host_a_logon: user.name\n",
        group_by=["host.name", "user"],
    )
    try:
        backend.convert(SigmaCollection.from_yaml(incomplete_alias))
    except SigmaCorrelationFieldError as error:
        print(f"REJECTED: {type(error).__name__}: {error}")
        assert error.field == "user"
        assert error.source_rule == "host_b_logon"
    else:
        raise AssertionError("Conversion must fail when an alias mapping is missing")

    heading("3. Plain group-by field missing in a source rule: conversion is rejected")
    plain_field = correlation_yaml(aliases=None, group_by=["host.name", "user.name"])
    try:
        backend.convert(SigmaCollection.from_yaml(plain_field))
    except SigmaCorrelationFieldError as error:
        print(f"REJECTED: {type(error).__name__}: {error}")
        assert error.field == "user.name"
        assert error.source_rule == "host_b_logon"
    else:
        raise AssertionError("Conversion must fail for an unresolvable plain group-by field")

    heading("4. Backend without field normalization support: alias is rejected")
    no_norm_backend = TextQueryTestBackend()
    no_norm_backend.correlation_search_field_normalization_expression = None
    no_norm_backend.correlation_search_field_normalization_expression_joiner = None
    try:
        no_norm_backend.convert(SigmaCollection.from_yaml(with_alias))
    except SigmaCorrelationFieldError as error:
        print(f"REJECTED: {type(error).__name__}: {error}")
        assert error.field == "user"
    else:
        raise AssertionError("Conversion must fail when the backend cannot normalize aliases")

    heading("5. Pipeline fan-out of an aliased source field into several fields: rejected")
    fanout_pipeline = ProcessingPipeline(
        [
            ProcessingItem(
                FieldMappingTransformation(
                    {"user.name": ["user.name.windows", "user.name.upn"], "subject": "sub"}
                )
            )
        ]
    )
    fanout_backend = TextQueryTestBackend(processing_pipeline=fanout_pipeline)
    try:
        fanout_backend.convert(SigmaCollection.from_yaml(with_alias))
    except Exception as error:  # noqa: BLE001 - demo prints whichever concrete error fires
        print(f"REJECTED: {type(error).__name__}: {error}")
        assert "host_a_logon" in str(error)
        assert "user" in str(error)
    else:
        raise AssertionError("Conversion must fail when one source field fans out")

    heading("All checks behaved as expected")


if __name__ == "__main__":
    main()
