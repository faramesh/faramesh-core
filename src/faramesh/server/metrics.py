# src/faramesh/server/metrics.py
"""Basic Prometheus metrics for Faramesh."""
from __future__ import annotations

from fastapi import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

# Metrics
requests_total = Counter(
    "faramesh_requests_total",
    "Total number of requests",
    ["method", "endpoint", "status"]
)

errors_total = Counter(
    "faramesh_errors_total",
    "Total number of errors",
    ["error_type"]
)

actions_total = Counter(
    "faramesh_actions_total",
    "Total number of actions",
    ["status", "tool"]
)

action_duration_seconds = Histogram(
    "faramesh_action_duration_seconds",
    "Action processing duration in seconds",
    ["tool", "operation"]
)


def get_metrics_response() -> Response:
    """Get Prometheus metrics as HTTP response."""
    try:
        metrics_content = generate_latest()
    except Exception as e:
        import logging
        logging.error(f"Failed to generate metrics: {e}")
        # Return empty metrics on error rather than crashing
        metrics_content = b"# Error generating metrics\n"
    
    return Response(
        content=metrics_content,
        media_type=CONTENT_TYPE_LATEST
    )
