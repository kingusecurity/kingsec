"""Inbound web adapter — FastAPI HTTP surface for KingSec.

This is a driving adapter: it depends on the ``ServiceAPI`` port (not on
concrete use cases or infrastructure). The composition root wires the port
to a concrete implementation at startup.

Modules:
    app          FastAPI application factory
    routes       HTTP endpoints (APIRouter)
    schemas      Pydantic request/response models
    dependencies FastAPI DI (resolve ServiceAPI from the container)
    error_handlers Exception → HTTP status mapping
    sse          Server-Sent Events for live assessment progress
"""
