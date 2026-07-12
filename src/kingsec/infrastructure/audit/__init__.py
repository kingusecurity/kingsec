"""Infrastructure audit trail — middleware and DI wiring.

The ``AuditContextMiddleware`` lives in ``infrastructure.middleware.context``
and is re-exported here for convenience.
"""

from kingsec.infrastructure.middleware.context import AuditContextMiddleware

__all__ = ["AuditContextMiddleware"]
