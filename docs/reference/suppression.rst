Filter Suppression Provenance
==============================

When a :class:`~sigma.filters.SigmaFilter` matches a rule, pySigma appends a
rewritten copy of its filter condition to the rule condition and stores copies
of its filter detections under generated ``_filt_<random>_<identifier>`` names.
The :mod:`sigma.suppression` module adds structured provenance on top of this
mechanism without changing the detection logic: it records which filter rule
and which part of its filter condition caused each suppressed condition node in
the final rule.

Provenance only follows condition nodes that are actually present in the final
rule:

* a filter that does not match a rule (different logsource, unknown rule
  reference, or a correlation rule) contributes no source at all;
* the source is attached to every filter-owned condition subtree, including the
  subtree below a ``NOT`` operator and subtrees of several stacked filters;
* one filter applied to several rules produces one independent
  :class:`~sigma.suppression.SuppressionSource` per rule;
* if a later processing transformation removes the filter detection nodes, the
  source disappears with them.

SuppressionSource
-----------------

.. autoclass:: sigma.suppression.SuppressionSource
   :members:
   :undoc-members:

Functions
---------

.. automodule:: sigma.suppression
   :members:
   :undoc-members:
   :exclude-members: SuppressionSource
