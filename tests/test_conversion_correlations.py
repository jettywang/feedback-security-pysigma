import pytest
from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaBackendError, SigmaConversionError
from sigma.processing.pipeline import ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.postprocessing import EmbedQueryTransformation
from .test_conversion_base import test_backend


@pytest.fixture
def event_count_correlation_rule():
    return SigmaCollection.from_yaml("""
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons for a single user (possible brute force attack)
status: test
correlation:
    type: event_count
    rules:
        - failed_logon
    group-by:
        - TargetUserName
        - TargetDomainName
        - fieldB
    timespan: 5m
    condition:
        gte: 10
fields:
    - SubjectUserName
    - TargetUserName
    - Computer
            """)


def test_event_count_correlation_single_rule_with_grouping(
    test_backend, event_count_correlation_rule
):
    assert test_backend.convert(event_count_correlation_rule) == ["""EventID=4625
| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName, mappedB
| where event_count >= 10"""]


def test_correlation_without_normalization_support(
    monkeypatch, test_backend, event_count_correlation_rule
):
    monkeypatch.setattr(test_backend, "correlation_search_field_normalization_expression", None)
    assert test_backend.convert(event_count_correlation_rule) == ["""EventID=4625
| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName, mappedB
| where event_count >= 10"""]


def test_generate_query_without_referenced_rules_expression(
    monkeypatch, test_backend, event_count_correlation_rule
):
    monkeypatch.setattr(test_backend, "referenced_rules_expression", None)
    monkeypatch.setattr(test_backend, "referenced_rules_expression_joiner", None)
    assert test_backend.convert(event_count_correlation_rule) == ["""EventID=4625
| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName, mappedB
| where event_count >= 10"""]


def test_event_count_correlation_single_rule_with_fields(
    monkeypatch, test_backend, event_count_correlation_rule
):
    monkeypatch.setattr(test_backend, "correlation_fields_expression", {"test": " {fields}"})
    monkeypatch.setattr(
        test_backend, "correlation_fields_field_expression", {"test": "values({field}) as {field}"}
    )
    monkeypatch.setattr(test_backend, "correlation_fields_field_expression_joiner", {"test": " "})
    monkeypatch.setattr(
        test_backend,
        "event_count_aggregation_expression",
        {"test": "| aggregate window={timespan} count() as event_count{fields}{groupby}"},
    )

    assert test_backend.convert(event_count_correlation_rule) == ["""EventID=4625
| aggregate window=5min count() as event_count values(SubjectUserName) as SubjectUserName values(Computer) as Computer by TargetUserName, TargetDomainName, mappedB
| where event_count >= 10"""]


@pytest.fixture
def value_count_correlation_rule():
    return SigmaCollection.from_yaml("""
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons for diffrerent users (possible password spraying attack)
status: test
correlation:
    type: value_count
    rules:
        - failed_logon
    timespan: 5m
    condition:
        gte: 100
        field: TargetUserName
            """)


def test_value_count_correlation_single_rule_without_grouping(
    test_backend, value_count_correlation_rule
):
    assert test_backend.convert(value_count_correlation_rule) == ["""EventID=4625
| aggregate window=5min value_count(TargetUserName) as value_count
| where value_count >= 100"""]


@pytest.fixture
def temporal_correlation_rule():
    temporal_correlation_rule = SigmaCollection.from_yaml("""
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
fields:
    - SubjectUserName
    - TargetUserName
---
title: Successful logon
name: successful_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
fields:
    - SubjectUserName
    - TargetUserName
    - LogonType
---
title: Failed and successful logons for a single user
status: test
correlation:
    type: temporal
    rules:
        - failed_logon
        - successful_logon
    timespan: 5m
    group-by:
        - TargetUserName
        - TargetDomainName
            """)

    return temporal_correlation_rule


def test_temporal_correlation_multi_rule_without_condition(test_backend, temporal_correlation_rule):
    assert test_backend.convert(temporal_correlation_rule) == [
        """subsearch { EventID=4625 | set event_type="failed_logon" }
subsearch { EventID=4624 | set event_type="successful_logon" }

| temporal window=5min eventtypes=failed_logon,successful_logon by TargetUserName, TargetDomainName

| where eventtype_count >= 2"""
    ]


def test_temporal_correlation_multi_rule_with_typing_expression(
    monkeypatch, test_backend, temporal_correlation_rule
):
    monkeypatch.setattr(
        test_backend,
        "temporal_correlation_query",
        {"test": "{search}\n{typing}\n\n{aggregate}\n\n{condition}"},
    )
    monkeypatch.setattr(
        test_backend, "correlation_search_multi_rule_query_expression", "( {query} )"
    )
    monkeypatch.setattr(
        test_backend, "correlation_search_multi_rule_query_expression_joiner", " or "
    )
    monkeypatch.setattr(test_backend, "typing_expression", "| eval event_type=case({queries})")
    monkeypatch.setattr(test_backend, "typing_rule_query_expression_joiner", ", ")
    monkeypatch.setattr(test_backend, "typing_rule_query_expression", '{query}, "{ruleid}"')
    assert test_backend.convert(temporal_correlation_rule) == [
        """( EventID=4625 ) or ( EventID=4624 )
| eval event_type=case(EventID=4625, "failed_logon", EventID=4624, "successful_logon")

| temporal window=5min eventtypes=failed_logon,successful_logon by TargetUserName, TargetDomainName

| where eventtype_count >= 2"""
    ]


def test_temporal_correlation_multi_rule_with_referenced_rules_fields(
    monkeypatch, test_backend, temporal_correlation_rule
):

    monkeypatch.setattr(test_backend, "correlation_fields_expression", {"test": " {fields}"})
    monkeypatch.setattr(
        test_backend, "correlation_fields_field_expression", {"test": "values({field}) as {field}"}
    )
    monkeypatch.setattr(test_backend, "correlation_fields_field_expression_joiner", {"test": " "})

    monkeypatch.setattr(
        test_backend,
        "temporal_aggregation_expression",
        {
            "test": "| aggregate window={timespan} count() as event_count{fields}{groupby}\n| temporal window={timespan} eventtypes={referenced_rules}{groupby}"
        },
    )
    assert test_backend.convert(temporal_correlation_rule) == [
        """subsearch { EventID=4625 | set event_type="failed_logon" }
subsearch { EventID=4624 | set event_type="successful_logon" }

| aggregate window=5min count() as event_count values(SubjectUserName) as SubjectUserName values(LogonType) as LogonType by TargetUserName, TargetDomainName
| temporal window=5min eventtypes=failed_logon,successful_logon by TargetUserName, TargetDomainName

| where eventtype_count >= 2"""
    ]


def test_referenced_rule_expression_used_but_not_defined(
    monkeypatch, test_backend, temporal_correlation_rule
):
    monkeypatch.setattr(test_backend, "referenced_rules_expression", None)
    monkeypatch.setattr(test_backend, "referenced_rules_expression_joiner", None)
    with pytest.raises(SigmaBackendError, match="referenced rule expression"):
        test_backend.convert(temporal_correlation_rule)


@pytest.fixture
def temporal_ordered_correlation_rule():
    return SigmaCollection.from_yaml("""
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Successful logon
name: successful_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
---
title: Discovery activity
name: discovery_activity
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - whoami
            - dsquery
            - net group
    condition: selection
---
title: Failed and successful logons for a single user
status: test
correlation:
    type: temporal_ordered
    rules:
        - failed_logon
        - successful_logon
        - discovery_activity
    timespan: 1h
    aliases:
        user:
            failed_logon: TargetUserName
            successful_logon: TargetUserName
            discovery_activity: User
        domain:
            failed_logon: TargetDomainName
            successful_logon: TargetDomainName
            discovery_activity: Domain
        mapped:
            failed_logon: fieldB
            successful_logon: fieldC
            discovery_activity: fieldD
    group-by:
        - user
        - domain
        - mapped
    condition:
        gte: 2
            """)


def test_temporal_ordered_correlation_multi_rule_with_condition_and_field_normalization(
    test_backend, temporal_ordered_correlation_rule
):
    assert test_backend.convert(temporal_ordered_correlation_rule) == [
        """subsearch { EventID=4625 | set event_type="failed_logon" | set user=TargetUserName | set domain=TargetDomainName | set mapped=mappedB }
subsearch { EventID=4624 | set event_type="successful_logon" | set user=TargetUserName | set domain=TargetDomainName | set mapped=fieldC }
subsearch { CommandLine in ("*whoami*", "*dsquery*", "*net group*") | set event_type="discovery_activity" | set user=User | set domain=Domain | set mapped=fieldD }
| temporal ordered=true window=1h eventtypes=failed_logon,successful_logon,discovery_activity by user, domain, mapped
| where eventtype_count >= 2 and eventtype_order=failed_logon,successful_logon,discovery_activity"""
    ]


def test_correlation_timespan_in_seconds(monkeypatch, test_backend, event_count_correlation_rule):
    monkeypatch.setattr(test_backend, "timespan_seconds", True)
    assert test_backend.convert(event_count_correlation_rule) == ["""EventID=4625
| aggregate window=300 count() as event_count by TargetUserName, TargetDomainName, mappedB
| where event_count >= 10"""]


def test_correlation_no_aggregation_expression(
    monkeypatch, test_backend, value_count_correlation_rule
):
    monkeypatch.setattr(test_backend, "groupby_expression_nofield", {"test": " by nothing"})
    assert test_backend.convert(value_count_correlation_rule) == ["""EventID=4625
| aggregate window=5min value_count(TargetUserName) as value_count by nothing
| where value_count >= 100"""]


def test_correlation_generate_rule(test_backend):
    rule_collection = SigmaCollection.from_yaml("""
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons for a single user (possible brute force attack)
status: test
correlation:
    type: event_count
    rules:
        - failed_logon
    generate: true
    group-by:
        - TargetUserName
        - TargetDomainName
    timespan: 5m
    condition:
        gte: 10
            """)
    assert test_backend.convert(rule_collection) == [
        "EventID=4625",
        """EventID=4625
| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName
| where event_count >= 10""",
    ]


def test_correlation_generate_chained_rule(test_backend):
    rule_collection = SigmaCollection.from_yaml("""
title: Successful login
name: successful_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 528
            - 4624
    condition: selection
---
title: Single failed login
name: failed_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 529
            - 4625
    condition: selection
---
title: Multiple failed logons
name: multiple_failed_login
correlation:
    type: event_count
    rules:
        - failed_login
    generate: true
    group-by:
        - User
    timespan: 10m
    condition:
        gte: 10
---
title: Multiple Failed Logins Followed by Successful Login
status: test
correlation:
    type: temporal_ordered
    rules:
        - multiple_failed_login
        - successful_login
    generate: true
    group-by:
        - User
    timespan: 10m
            """)

    assert test_backend.convert(rule_collection) == [
        """EventID in (528, 4624)""",
        """EventID in (529, 4625)""",
        """EventID in (529, 4625)
| aggregate window=10min count() as event_count by User
| where event_count >= 10""",
        """subsearch { EventID in (529, 4625)\n| aggregate window=10min count() as event_count by User\n| where event_count >= 10 | set event_type="multiple_failed_login" }
subsearch { EventID in (528, 4624) | set event_type="successful_login" }
| temporal ordered=true window=10min eventtypes=multiple_failed_login,successful_login by User
| where eventtype_count >= 2 and eventtype_order=multiple_failed_login,successful_login""",
    ]


def test_correlation_chained_rule_without_generate(test_backend):
    rule_collection = SigmaCollection.from_yaml("""
title: Successful login
name: successful_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 528
            - 4624
    condition: selection
---
title: Single failed login
name: failed_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 529
            - 4625
    condition: selection
---
title: Multiple failed logons
name: multiple_failed_login
correlation:
    type: event_count
    rules:
        - failed_login
    generate: false
    group-by:
        - User
    timespan: 10m
    condition:
        gte: 10
---
title: Multiple Failed Logins Followed by Successful Login
status: test
correlation:
    type: temporal_ordered
    rules:
        - multiple_failed_login
        - successful_login
    generate: false
    group-by:
        - User
    timespan: 10m
            """)

    assert test_backend.convert(rule_collection) == [
        """subsearch { EventID in (529, 4625)\n| aggregate window=10min count() as event_count by User\n| where event_count >= 10 | set event_type="multiple_failed_login" }
subsearch { EventID in (528, 4624) | set event_type="successful_login" }
| temporal ordered=true window=10min eventtypes=multiple_failed_login,successful_login by User
| where eventtype_count >= 2 and eventtype_order=multiple_failed_login,successful_login""",
    ]


def test_correlation_not_supported(monkeypatch, test_backend, event_count_correlation_rule):
    monkeypatch.setattr(test_backend, "correlation_methods", None)
    with pytest.raises(NotImplementedError, match="Backend does not support correlation"):
        test_backend.convert(event_count_correlation_rule)


def test_correlation_method_not_supported(test_backend, event_count_correlation_rule):
    with pytest.raises(SigmaConversionError, match="Correlation method 'invalid' is not supported"):
        test_backend.convert(event_count_correlation_rule, correlation_method="invalid")


def test_correlation_method_no_supported_for_correlation_type(
    monkeypatch, test_backend, event_count_correlation_rule
):
    monkeypatch.setattr(
        test_backend,
        "correlation_methods",
        {"test": "Test correlation method", "another": "Another correlation method"},
    )
    with pytest.raises(
        SigmaConversionError,
        match="Correlation method 'another' is not supported by backend for correlation type 'event_count'",
    ):
        test_backend.convert(event_count_correlation_rule, correlation_method="another")


def test_correlation_type_not_supported(monkeypatch, test_backend, event_count_correlation_rule):
    monkeypatch.setattr(test_backend, "default_correlation_query", None)
    with pytest.raises(
        NotImplementedError, match="Correlation rule type 'event_count' is not supported"
    ):
        test_backend.convert(event_count_correlation_rule)


def test_correlation_normalization_not_supported(
    monkeypatch, test_backend, temporal_ordered_correlation_rule
):
    monkeypatch.setattr(test_backend, "correlation_search_field_normalization_expression", None)
    monkeypatch.setattr(
        test_backend, "correlation_search_field_normalization_expression_joiner", None
    )
    with pytest.raises(
        NotImplementedError, match="Correlation field normalization is not supported"
    ):
        test_backend.convert(temporal_ordered_correlation_rule)


def test_correlation_query_postprocessing(event_count_correlation_rule):
    test_backend = TextQueryTestBackend(
        ProcessingPipeline(
            postprocessing_items=[
                QueryPostprocessingItem(EmbedQueryTransformation(prefix="[ ", suffix=" ]"))
            ]
        )
    )
    assert test_backend.convert(event_count_correlation_rule) == ["""[ EventID=4625
| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName, fieldB
| where event_count >= 10 ]"""]


def test_correlation_subqueries_finalization(monkeypatch, event_count_correlation_rule):
    test_backend = TextQueryTestBackend(
        ProcessingPipeline(
            postprocessing_items=[
                QueryPostprocessingItem(EmbedQueryTransformation(prefix="[ ", suffix=" ]"))
            ]
        )
    )
    monkeypatch.setattr(test_backend, "finalize_correlation_subqueries", True)
    assert test_backend.convert(event_count_correlation_rule) == ["""[ [ EventID=4625 ]
| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName, fieldB
| where event_count >= 10 ]"""]


# Tests for new correlation types: value_sum, value_avg, value_percentile
@pytest.fixture
def value_sum_correlation_rule():
    return SigmaCollection.from_yaml("""
title: Transaction event
name: transaction_event
status: test
logsource:
    product: banking
detection:
    selection:
        EventType: transaction
    condition: selection
---
title: High value sum in short time (possible fraud)
status: test
correlation:
    type: value_sum
    rules:
        - transaction_event
    group-by:
        - AccountID
    timespan: 10m
    condition:
        gte: 10000
        field: Amount
            """)


def test_value_sum_correlation_single_rule_with_grouping(test_backend, value_sum_correlation_rule):
    assert test_backend.convert(value_sum_correlation_rule) == ["""EventType="transaction"
| aggregate window=10min sum(Amount) as value_sum by AccountID
| where value_sum >= 10000"""]


@pytest.fixture
def value_avg_correlation_rule():
    return SigmaCollection.from_yaml("""
title: API response event
name: api_response
status: test
logsource:
    product: api
detection:
    selection:
        EventType: api_response
    condition: selection
---
title: High average response time
status: test
correlation:
    type: value_avg
    rules:
        - api_response
    group-by:
        - Endpoint
    timespan: 5m
    condition:
        gte: 1000
        field: ResponseTime
            """)


def test_value_avg_correlation_single_rule_with_grouping(test_backend, value_avg_correlation_rule):
    assert test_backend.convert(value_avg_correlation_rule) == ["""EventType="api_response"
| aggregate window=5min avg(ResponseTime) as value_avg by Endpoint
| where value_avg >= 1000"""]


@pytest.fixture
def value_percentile_correlation_rule():
    return SigmaCollection.from_yaml("""
title: Network traffic event
name: network_traffic
status: test
logsource:
    product: network
detection:
    selection:
        EventType: network_traffic
    condition: selection
---
title: High percentile latency
status: test
correlation:
    type: value_percentile
    rules:
        - network_traffic
    group-by:
        - SourceIP
    timespan: 15m
    condition:
        gte: 500
        field: Latency
        percentile: 95
            """)


def test_value_percentile_correlation_single_rule_with_grouping(
    test_backend, value_percentile_correlation_rule
):
    assert test_backend.convert(value_percentile_correlation_rule) == [
        """EventType="network_traffic"
| aggregate window=15min percentile(Latency, 95) as value_percentile by SourceIP
| where value_percentile >= 500"""
    ]


@pytest.fixture
def value_median_correlation_rule():
    return SigmaCollection.from_yaml("""
title: API response event
name: api_response
status: test
logsource:
    product: api
detection:
    selection:
        EventType: api_response
    condition: selection
---
title: High median response time
status: test
correlation:
    type: value_median
    rules:
        - api_response
    group-by:
        - Endpoint
    timespan: 5m
    condition:
        gte: 1000
        field: ResponseTime
            """)


def test_value_median_correlation_single_rule_with_grouping(
    test_backend, value_median_correlation_rule
):
    assert test_backend.convert(value_median_correlation_rule) == ["""EventType="api_response"
| aggregate window=5min median(ResponseTime) as value_median by Endpoint
| where value_median >= 1000"""]


def test_value_percentile_correlation_missing_percentile(test_backend):
    """Test that missing percentile attribute raises SigmaConversionError for value_percentile correlation"""
    correlation_rule = SigmaCollection.from_yaml("""
title: Network traffic event
name: network_traffic
status: test
logsource:
    product: network
detection:
    selection:
        EventType: network_traffic
    condition: selection
---
title: High percentile latency without percentile
status: test
correlation:
    type: value_percentile
    rules:
        - network_traffic
    group-by:
        - SourceIP
    timespan: 15m
    condition:
        gte: 500
        field: Latency
            """)
    with pytest.raises(
        SigmaConversionError,
        match="Percentile must be specified in condition for value_percentile correlation type",
    ):
        test_backend.convert(correlation_rule)


def test_correlation_rule_callback(test_backend):
    """Test that callback is invoked for correlation rules"""
    correlation_rule = SigmaCollection.from_yaml("""
title: Test event
name: test_event
status: test
logsource:
    product: test
detection:
    selection:
        EventID: 100
    condition: selection
---
title: Event count correlation
status: test
correlation:
    type: event_count
    rules:
        - test_event
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 5
            """)

    callback_invocations = []

    def test_callback(rule, output_format, index, query, result):
        callback_invocations.append(
            {
                "rule": rule,
                "output_format": output_format,
                "index": index,
                "query": query,
                "result": result,
            }
        )
        return result + " /* modified by callback */"

    result = test_backend.convert(correlation_rule, callback=test_callback)

    # Verify callback was invoked - once for the rule conversion and once for the correlation
    assert len(callback_invocations) == 2
    # The second invocation should be for the correlation rule
    assert "aggregate window" in str(callback_invocations[1]["result"])
    assert "modified by callback" in result[-1]


def test_correlation_rule_callback_skip_result(test_backend):
    """Test that callback can skip results by returning None for correlation rules"""
    callback_calls = []

    def test_callback(rule, output_format, index, query, result):
        callback_calls.append((rule, output_format, index, query, result))
        # Skip the result
        return None

    rule_collection = SigmaCollection.from_yaml("""
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons for a single user (possible brute force attack)
status: test
correlation:
    type: event_count
    rules:
        - failed_logon
    group-by:
        - TargetUserName
        - TargetDomainName
    timespan: 5m
    condition:
        gte: 10
        """)

    result = test_backend.convert(rule_collection, callback=test_callback)
    assert result == []
    assert len(callback_calls) == 2


def test_finish_query_correlation_rule_only(test_backend):
    """Test that finish_query can wrap correlation queries without affecting subqueries."""
    from sigma.correlations import SigmaCorrelationRule

    class SearchWrapperCorrelationBackend(TextQueryTestBackend):
        def finish_query(self, rule, query, state):
            # Only wrap correlation rules, not regular rules
            if isinstance(rule, SigmaCorrelationRule):
                return f"search({query})"
            return query

    backend = SearchWrapperCorrelationBackend()
    rule_collection = SigmaCollection.from_yaml("""
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons
status: test
correlation:
    type: event_count
    rules:
        - failed_logon
    generate: true
    group-by:
        - TargetUserName
        - TargetDomainName
    timespan: 5m
    condition:
        gte: 10
        """)
    result = backend.convert(rule_collection)
    # First query is regular rule (not wrapped)
    assert result[0] == "EventID=4625"
    # Second query is correlation rule (wrapped)
    assert (
        result[1]
        == "search(EventID=4625\n| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName\n| where event_count >= 10)"
    )


def test_finish_query_regular_rule_only():
    """Test that finish_query can wrap regular rule queries without affecting correlation."""
    from sigma.correlations import SigmaCorrelationRule

    class SearchWrapperRegularBackend(TextQueryTestBackend):
        def finish_query(self, rule, query, state):
            # Only wrap regular rules, not correlation rules
            if not isinstance(rule, SigmaCorrelationRule):
                return f"search({query})"
            return query

    backend = SearchWrapperRegularBackend()
    rule_collection = SigmaCollection.from_yaml("""
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons
status: test
correlation:
    type: event_count
    rules:
        - failed_logon
    generate: true
    group-by:
        - TargetUserName
        - TargetDomainName
    timespan: 5m
    condition:
        gte: 10
        """)
    result = backend.convert(rule_collection)
    # First query is regular rule (wrapped)
    assert result[0] == "search(EventID=4625)"
    # Second query is correlation rule (not wrapped, but contains wrapped subquery)
    assert (
        result[1]
        == "search(EventID=4625)\n| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName\n| where event_count >= 10"
    )


def test_finish_query_both_correlation_and_subqueries():
    """Test that finish_query can wrap both correlation queries and their subqueries."""
    from sigma.correlations import SigmaCorrelationRule

    class SearchWrapperAllBackend(TextQueryTestBackend):
        def finish_query(self, rule, query, state):
            return f"search({query})"

    backend = SearchWrapperAllBackend()
    rule_collection = SigmaCollection.from_yaml("""
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons
status: test
correlation:
    type: event_count
    rules:
        - failed_logon
    generate: true
    group-by:
        - TargetUserName
        - TargetDomainName
    timespan: 5m
    condition:
        gte: 10
        """)
    result = backend.convert(rule_collection)
    # First query is regular rule (wrapped)
    assert result[0] == "search(EventID=4625)"
    # Second query is correlation rule (wrapped, and contains wrapped subquery)
    assert (
        result[1]
        == "search(search(EventID=4625)\n| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName\n| where event_count >= 10)"
    )


def test_finish_query_temporal_correlation_with_subqueries():
    """Test that finish_query wraps temporal correlation queries and their subqueries."""
    from sigma.correlations import SigmaCorrelationRule

    class SearchWrapperAllBackend(TextQueryTestBackend):
        def finish_query(self, rule, query, state):
            return f"search({query})"

    backend = SearchWrapperAllBackend()
    rule_collection = SigmaCollection.from_yaml("""
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Successful logon
name: successful_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
---
title: Failed then successful logon
status: test
correlation:
    type: temporal
    rules:
        - failed_logon
        - successful_logon
    generate: true
    group-by:
        - TargetUserName
        - TargetDomainName
    timespan: 5m
        """)
    result = backend.convert(rule_collection)
    # First two queries are regular rules (wrapped)
    assert result[0] == "search(EventID=4625)"
    assert result[1] == "search(EventID=4624)"
    # Third query is temporal correlation (wrapped, with wrapped subqueries)
    # The correlation should contain the wrapped subqueries
    assert "subsearch { search(EventID=4625)" in result[2]
    assert "subsearch { search(EventID=4624)" in result[2]
    # And the entire correlation should be wrapped too
    assert result[2].startswith("search(")


def test_correlation_ruleid_is_escaped_in_multi_rule_search_and_typing(test_backend):
    rule_collection = SigmaCollection.from_yaml("""
title: Rule one
name: 'bad"name'
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Rule two
name: 'bad"name2'
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 2
    condition: selection
---
title: Temporal correlation with typing
status: test
correlation:
    type: temporal
    rules:
        - 'bad"name'
        - 'bad"name2'
    group-by:
        - User
    timespan: 5m
    """)

    result = test_backend.convert(rule_collection)
    assert 'set event_type="bad\\"name"' in result[0]
    assert 'set event_type="bad\\"name2"' in result[0]

    monkeypatch_backend = TextQueryTestBackend()
    monkeypatch_backend.typing_expression = "| eval event_type=case({queries})"
    monkeypatch_backend.typing_rule_query_expression = '{query}, "{ruleid}"'
    monkeypatch_backend.typing_rule_query_expression_joiner = ", "

    result_with_typing = monkeypatch_backend.convert(rule_collection)
    assert '"bad\\"name"' in result_with_typing[0]
    assert '"bad\\"name2"' in result_with_typing[0]


def temporal_correlation_with_rule_names(
    correlation_type: str, first_name: str, second_name: str
) -> SigmaCollection:
    return SigmaCollection.from_yaml(f"""
title: Rule one
name: '{first_name}'
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Rule two
name: '{second_name}'
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 2
    condition: selection
---
title: Temporal correlation
status: test
correlation:
    type: {correlation_type}
    rules:
        - '{first_name}'
        - '{second_name}'
    group-by:
        - User
    timespan: 5m
""")


@pytest.mark.parametrize(
    "correlation_type,expected_prefix",
    [
        ("temporal", "| temporal window=5min"),
        ("temporal_ordered", "| temporal ordered=true window=5min"),
    ],
)
def test_correlation_referenced_rules_are_escaped(test_backend, correlation_type, expected_prefix):
    result = test_backend.convert(
        temporal_correlation_with_rule_names(correlation_type, 'bad"name', "rule two")
    )
    assert f'{expected_prefix} eventtypes="bad\\"name","rule two" by User' in result[0]


def test_correlation_referenced_rules_plain_names_unchanged(test_backend):
    result = test_backend.convert(
        temporal_correlation_with_rule_names("temporal", "rule-one_1.a", "rule_two")
    )
    assert "| temporal window=5min eventtypes=rule-one_1.a,rule_two by User" in result[0]


def test_correlation_condition_fieldref_is_escaped(test_backend):
    rule_collection = SigmaCollection.from_yaml("""
title: API response event
name: api_response
status: test
logsource:
    product: api
detection:
    selection:
        EventType: api_response
    condition: selection
---
title: Value count with special fieldref
status: test
correlation:
    type: value_count
    rules:
        - api_response
    timespan: 5m
    condition:
        gte: 10
        field: field with space
    """)

    assert test_backend.convert(rule_collection) == ["""EventType=\"api_response\"
| aggregate window=5min value_count('field with space') as value_count
| where value_count >= 10"""]


def test_correlation_alias_mapping_field_is_escaped(test_backend):
    rule_collection = SigmaCollection.from_yaml("""
title: Rule one
name: rule_one
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Rule two
name: rule_two
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 2
    condition: selection
---
title: Temporal ordered with aliases
status: test
correlation:
    type: temporal_ordered
    rules:
        - rule_one
        - rule_two
    aliases:
        alias space:
            rule_one: field with space
            rule_two: other field
    group-by:
        - alias space
    timespan: 5m
    condition:
        gte: 2
    """)

    result = test_backend.convert(rule_collection)
    assert "set 'alias space'='field with space'" in result[0]
    assert "set 'alias space'='other field'" in result[0]


def test_correlation_rule_callback_skip_result_only(test_backend):
    """Test that callback can skip results by returning None"""
    correlation_rule = SigmaCollection.from_yaml("""
title: Test event
name: test_event
status: test
logsource:
    product: test
detection:
    selection:
        EventID: 100
    condition: selection
---
title: Event count correlation
status: test
correlation:
    type: event_count
    rules:
        - test_event
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 5
            """)

    def skip_callback(rule, output_format, index, query, result):
        return None  # Skip all results

    result = test_backend.convert(correlation_rule, callback=skip_callback)

    # Verify no results were returned (both rule and correlation skipped)
    assert len(result) == 0


# Correlation timespan capability tests
from datetime import datetime, timedelta, timezone

from sigma.backends.test import FixedWindowTestBackend
from sigma.correlations import (
    SIGMA_TIMESPAN_APPROXIMATION_MARKER,
    SigmaCorrelationTimespan,
    SigmaCorrelationTimespanCapability,
    SigmaCorrelationWindowMode,
)
from sigma.conversion.base import SigmaCorrelationConversionResult
from sigma.exceptions import SigmaCorrelationTimespanNotSupportedError, SigmaValueError
from sigma.matching import Event, EventLogSource, SigmaMatcher


def _correlation_timespan_rule(timespan: str) -> SigmaCollection:
    return SigmaCollection.from_yaml(f"""
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons
status: test
correlation:
    type: event_count
    rules:
        - failed_logon
    group-by:
        - TargetUserName
    timespan: {timespan}
    condition:
        gte: 2
            """)


class TestCorrelationTimespanCapabilityDeclaration:
    def test_declared_capability_is_exposed(self, test_backend):
        capability = test_backend.get_correlation_timespan_capability()
        assert capability.declared
        assert capability.min_unit == "s"
        assert capability.supports_sliding
        assert not capability.supports_fixed

    def test_undeclared_capability_used_for_legacy_backends(self):
        backend = TextQueryTestBackend()
        backend.correlation_timespan_min_unit = None
        backend.correlation_window_modes = None
        capability = backend.get_correlation_timespan_capability()
        assert not capability.declared
        assert capability.window_modes == frozenset()

    @pytest.mark.parametrize("min_unit", ["ms", "min", "S", ""])
    def test_invalid_min_unit_rejected(self, min_unit):
        with pytest.raises(SigmaValueError, match="Invalid correlation timespan minimum unit"):
            SigmaCorrelationTimespanCapability(min_unit=min_unit)

    def test_invalid_window_mode_rejected(self):
        with pytest.raises(SigmaValueError, match="Invalid correlation window mode"):
            SigmaCorrelationTimespanCapability(window_modes=frozenset({"rolling"}))

    def test_capability_without_correlation_support_rejected(self):
        backend = TextQueryTestBackend()
        backend.correlation_methods = None
        backend.correlation_window_modes = frozenset({SigmaCorrelationWindowMode.SLIDING})
        with pytest.raises(SigmaBackendError, match="does not support correlation rules"):
            backend._validate_correlation_timespan_capability()


class TestCorrelationTimespanExactness:
    def test_exact_sliding_window_is_accepted(self, test_backend):
        rules = _correlation_timespan_rule("5m")
        assert test_backend.convert(rules) == ["""EventID=4625
| aggregate window=5min count() as event_count by TargetUserName
| where event_count >= 2"""]
        resolution = rules[1].get_conversion_states()[0].metadata["correlation_timespan"]
        assert resolution["exact"] is True
        assert resolution["window_mode"] == "sliding"
        assert resolution["effective_spec"] == "5m"
        assert resolution["deviation_seconds"] == 0
        assert resolution["marker"] is None

    def test_fixed_window_backend_rejected_by_default(self):
        with pytest.raises(
            SigmaCorrelationTimespanNotSupportedError,
            match="fixed time buckets instead of a sliding window",
        ):
            FixedWindowTestBackend().convert(_correlation_timespan_rule("5m"))

    def test_fixed_window_rejection_returns_no_query(self):
        with pytest.raises(SigmaCorrelationTimespanNotSupportedError) as exc_info:
            FixedWindowTestBackend().convert(_correlation_timespan_rule("5m"))
        assert "cannot be represented exactly" in str(exc_info.value)

    def test_coarse_granularity_rejected_by_default(self, monkeypatch, test_backend):
        monkeypatch.setattr(test_backend, "correlation_timespan_min_unit", "m")
        with pytest.raises(
            SigmaCorrelationTimespanNotSupportedError,
            match="rounded up from 30s to 1m",
        ):
            test_backend.convert(_correlation_timespan_rule("30s"))

    def test_approximation_disabled_by_default(self, test_backend):
        assert test_backend.allow_correlation_timespan_approximation is False

    def test_explicit_approximation_marks_fixed_window_result(self):
        backend = FixedWindowTestBackend()
        backend.allow_correlation_timespan_approximation = True
        result = backend.convert(_correlation_timespan_rule("5m"))
        assert isinstance(result, SigmaCorrelationConversionResult)
        assert SIGMA_TIMESPAN_APPROXIMATION_MARKER in result.markers
        assert result.approximated
        assert result[0] == """EventID=4625
| aggregate window=5min count() as event_count by TargetUserName
| where event_count >= 2"""
        metadata = result.get_metadata()
        assert metadata["markers"] == [SIGMA_TIMESPAN_APPROXIMATION_MARKER]
        assert metadata["timespans"][0]["exact"] is False
        assert metadata["timespans"][0]["precision_exact"] is True
        assert metadata["timespans"][0]["semantics_exact"] is False
        assert "fixed time buckets" in metadata["notices"][0]

    def test_approximation_widens_and_marks_instead_of_simply_replacing_unit(
        self, monkeypatch, test_backend
    ):
        monkeypatch.setattr(test_backend, "correlation_timespan_min_unit", "m")
        monkeypatch.setattr(test_backend, "allow_correlation_timespan_approximation", True)
        result = test_backend.convert(_correlation_timespan_rule("30s"))
        assert isinstance(result, SigmaCorrelationConversionResult)
        assert SIGMA_TIMESPAN_APPROXIMATION_MARKER in result.markers
        # A naive unit replacement would emit 30s. The effective window must be the rounded-up
        # 1m duration so that it is never narrower than the requested window.
        assert "window=1min" in result[0]
        resolution = result.get_metadata()["timespans"][0]
        assert resolution["requested"] == "30s"
        assert resolution["effective_spec"] == "1m"
        assert resolution["effective_seconds"] == 60
        assert resolution["deviation_seconds"] == 30
        assert resolution["approximated"] is True
        assert resolution["marker"] == SIGMA_TIMESPAN_APPROXIMATION_MARKER

    def test_approximation_in_seconds_mode_uses_effective_seconds(self, monkeypatch, test_backend):
        monkeypatch.setattr(test_backend, "correlation_timespan_min_unit", "m")
        monkeypatch.setattr(test_backend, "allow_correlation_timespan_approximation", True)
        monkeypatch.setattr(test_backend, "timespan_seconds", True)
        result = test_backend.convert(_correlation_timespan_rule("90s"))
        assert "window=120" in result[0]
        assert result.get_metadata()["timespans"][0]["effective_seconds"] == 120

    def test_exact_granularity_multiple_is_not_marked(self, monkeypatch, test_backend):
        monkeypatch.setattr(test_backend, "correlation_timespan_min_unit", "m")
        rules = _correlation_timespan_rule("2m")
        result = test_backend.convert(rules)
        assert not isinstance(result, SigmaCorrelationConversionResult)
        resolution = rules[1].get_conversion_states()[0].metadata["correlation_timespan"]
        assert resolution["exact"] is True
        assert resolution["effective_spec"] == "2m"

    def test_explicitly_unsupported_window_mode_rejected(self, test_backend):
        with pytest.raises(
            SigmaValueError, match="does not support correlation window mode 'fixed'"
        ):
            test_backend.resolve_correlation_timespan(
                SigmaCorrelationTimespan("5m"), SigmaCorrelationWindowMode.FIXED
            )


class TestCorrelationWindowBoundaryAgainstReference:
    @staticmethod
    def _rule_yaml(timespan: str = "5m") -> str:
        return f"""
title: Base Rule
name: base_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field: "trigger"
    condition: selection
---
title: Correlation
name: correlation_rule
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - user
    timespan: {timespan}
    condition:
        gte: 2
"""

    def _events(self, base: datetime, offsets: list[int], user: str) -> list[Event]:
        ls = EventLogSource(category="test", product="test")
        return [
            Event(
                timestamp=base + timedelta(seconds=offset),
                logsource=ls,
                data={"field": "trigger", "user": user},
            )
            for offset in offsets
        ]

    def test_reference_window_includes_exact_boundary(self):
        # The reference matcher evicts entries strictly older than now - timespan. An event
        # exactly at the boundary therefore remains inside the window.
        collection = SigmaCollection.from_yaml(self._rule_yaml())
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with SigmaMatcher(collection) as matcher:
            matches = matcher.bulk_match(self._events(base, [0, 300], "edge"))
            assert any(m.rule.name == "correlation_rule" for m in matches)

    def test_reference_window_excludes_event_beyond_boundary(self):
        collection = SigmaCollection.from_yaml(self._rule_yaml())
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with SigmaMatcher(collection) as matcher:
            matches = matcher.bulk_match(self._events(base, [0, 301], "outside"))
            assert not any(m.rule.name == "correlation_rule" for m in matches)

    def test_exact_mode_agrees_with_reference_criterion_near_boundary(self, test_backend):
        collection = SigmaCollection.from_yaml(self._rule_yaml())
        result = test_backend.convert(collection)
        resolution = collection[1].get_conversion_states()[0].metadata["correlation_timespan"]
        assert resolution["exact"] is True
        assert resolution["window_mode"] == "sliding"
        assert resolution["effective_spec"] == "5m"
        assert test_backend.resolve_correlation_timespan(SigmaCorrelationTimespan("5m")).exact

        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        ls = EventLogSource(category="test", product="test")

        def triggers(offsets: list[int], user: str) -> bool:
            with SigmaMatcher(SigmaCollection.from_yaml(self._rule_yaml())) as matcher:
                return any(
                    m.rule.name == "correlation_rule"
                    for m in matcher.bulk_match(self._events(base, offsets, user))
                )

        assert triggers([0, 300], "boundary")
        assert not triggers([0, 301], "beyond")

    def test_cross_bucket_pair_is_inside_reference_sliding_window(self):
        # Two events 2 seconds apart, but straddling a fixed 1-minute bucket boundary.
        collection = SigmaCollection.from_yaml(self._rule_yaml("2m"))
        base = datetime(2026, 1, 1, 0, 0, 59, tzinfo=timezone.utc)
        with SigmaMatcher(collection) as matcher:
            matches = matcher.bulk_match(self._events(base, [0, 2], "alice"))
            assert any(m.rule.name == "correlation_rule" for m in matches)
        assert base.minute != (base + timedelta(seconds=2)).minute
        assert base.replace(second=0) != (base + timedelta(seconds=2)).replace(second=0)

    def test_cross_bucket_pair_is_not_silently_accepted_by_fixed_backend(self):
        # A fixed-bucket backend would separate these events into adjacent buckets, but they are
        # inside the requested sliding window. It must not emit a successful-looking query
        # without a marker.
        with pytest.raises(SigmaCorrelationTimespanNotSupportedError, match="fixed time buckets"):
            FixedWindowTestBackend().convert(_correlation_timespan_rule("2m"))

    def test_cross_bucket_pair_is_marked_when_approximation_allowed(self):
        backend = FixedWindowTestBackend()
        backend.allow_correlation_timespan_approximation = True
        result = backend.convert(_correlation_timespan_rule("2m"))
        assert SIGMA_TIMESPAN_APPROXIMATION_MARKER in result.markers
        metadata = result.get_metadata()["timespans"][0]
        assert metadata["semantics_exact"] is False
        assert metadata["window_mode"] == "fixed"
        assert metadata["approximated"] is True


class TestCorrelationTimespanEdgeCases:
    def test_legacy_backend_is_not_checked_or_marked(self, monkeypatch, test_backend):
        monkeypatch.setattr(test_backend, "correlation_timespan_min_unit", None)
        monkeypatch.setattr(test_backend, "correlation_window_modes", None)
        rules = _correlation_timespan_rule("30s")
        result = test_backend.convert(rules)
        assert not isinstance(result, SigmaCorrelationConversionResult)
        resolution = rules[1].get_conversion_states()[0].metadata["correlation_timespan"]
        assert resolution["verified"] is False
        assert resolution["exact"] is True

    def test_collect_errors_keeps_rejection_as_error(self):
        backend = FixedWindowTestBackend(collect_errors=True)
        result = backend.convert(_correlation_timespan_rule("5m"))
        assert result == []
        assert len(backend.errors) == 1
        error = backend.errors[0][1]
        assert isinstance(error, SigmaCorrelationTimespanNotSupportedError)
        assert "cannot be represented exactly" in str(error)

    def test_mixed_collection_retains_marker_for_approximated_rule(self):
        backend = FixedWindowTestBackend()
        backend.allow_correlation_timespan_approximation = True
        rules = SigmaCollection.from_yaml("""
title: Exact duration rule
name: exact_rule
status: test
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Approximated correlation
status: test
correlation:
    type: event_count
    rules:
        - exact_rule
    timespan: 2m
    condition:
        gte: 2
---
title: Another detection
name: another_rule
status: test
logsource:
    product: windows
detection:
    selection:
        EventID: 2
    condition: selection
""")
        result = backend.convert(rules)
        # The plain detection rule is not a correlation rule and must not add a marker itself.
        assert isinstance(result, SigmaCorrelationConversionResult)
        assert result.get_metadata()["markers"] == [SIGMA_TIMESPAN_APPROXIMATION_MARKER]
        assert len(result.get_metadata()["timespans"]) == 1
        assert result == backend.finalize(
            [
                result[0],
                result[1],
            ],
            "default",
        )

    def test_resolution_helper_reports_exact_capability(self, test_backend):
        resolution = test_backend.resolve_correlation_timespan(SigmaCorrelationTimespan("1h"))
        assert resolution.exact
        assert resolution.verified
        assert resolution.semantics_exact
        assert resolution.precision_exact
        assert resolution.window_mode == SigmaCorrelationWindowMode.SLIDING

    def test_fixed_window_resolution_reports_deviation_but_not_precision(self):
        resolution = FixedWindowTestBackend().resolve_correlation_timespan(
            SigmaCorrelationTimespan("5m")
        )
        assert not resolution.exact
        assert resolution.precision_exact
        assert not resolution.semantics_exact
        assert resolution.deviation_seconds == 0
        assert resolution.marker == SIGMA_TIMESPAN_APPROXIMATION_MARKER
        assert resolution.window_mode == SigmaCorrelationWindowMode.FIXED

    def test_result_marker_and_metadata_are_directly_accessible(self):
        backend = FixedWindowTestBackend()
        backend.allow_correlation_timespan_approximation = True
        result = backend.convert(_correlation_timespan_rule("5m"))
        assert SIGMA_TIMESPAN_APPROXIMATION_MARKER in result
        assert result.metadata["markers"] == [SIGMA_TIMESPAN_APPROXIMATION_MARKER]
        assert result.metadata == result.get_metadata()
