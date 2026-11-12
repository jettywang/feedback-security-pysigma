Correlations
============

The correlations module handles Sigma correlation rules that combine multiple detection
rules with temporal or statistical conditions.

SigmaCorrelationRule
--------------------

.. autoclass:: sigma.correlations.SigmaCorrelationRule
   :members:
   :undoc-members:
   :show-inheritance:

Correlation Types
-----------------

.. autoclass:: sigma.correlations.SigmaCorrelationType
   :members:
   :undoc-members:
   :show-inheritance:

Correlation Conditions
----------------------

.. autoclass:: sigma.correlations.SigmaCorrelationCondition
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.correlations.SigmaExtendedCorrelationCondition
   :members:
   :undoc-members:
   :show-inheritance:

Correlation Condition Tree
--------------------------

.. autoclass:: sigma.correlations.CorrelationConditionItem
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.correlations.CorrelationConditionAND
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.correlations.CorrelationConditionOR
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.correlations.CorrelationConditionNOT
   :members:
   :undoc-members:
   :show-inheritance:

Supporting Classes
------------------

.. autoclass:: sigma.correlations.SigmaRuleReference
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.correlations.SigmaCorrelationFieldAliases
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.correlations.SigmaCorrelationTimespan
   :members:
   :undoc-members:
   :show-inheritance:

Timespan Capabilities
---------------------

Correlation rules assume a sliding time window: every new event is evaluated against all events
of the same group within the preceding timespan. Backends can only implement this faithfully if
their target system supports the required granularity and window semantics. Backends declare
this with ``correlation_timespan_min_unit`` and ``correlation_window_modes`` on the backend class.

.. autoclass:: sigma.correlations.SigmaCorrelationWindowMode
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.correlations.SigmaCorrelationTimespanCapability
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.correlations.SigmaCorrelationTimespanResolution
   :members:
   :undoc-members:
   :show-inheritance:

.. autodata:: sigma.correlations.SIGMA_TIMESPAN_APPROXIMATION_MARKER

