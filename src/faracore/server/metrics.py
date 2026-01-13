# src/faracore/server/metrics.py
"""Basic Prometheus metrics for FaraCore."""
from __future__ import annotations

from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response

# Metrics
requests_total = Counter(
    "faracore_requests_total",
    "Total number of requests",
    ["method", "endpoint", "status"]
)

errors_total = Counter(
    "faracore_errors_total",
    "Total number of errors",
    ["error_type"]
)

actions_total = Counter(
    "faracore_actions_total",
    "Total number of actions",
    ["status", "tool"]
)

action_duration_seconds = Histogram(
    "faracore_action_duration_seconds",
    "Action processing duration in seconds",
    ["tool", "operation"]
)


def get_metrics_response() -> Response:
    """Get Prometheus metrics as HTTP response."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )
