"""Prometheus metrics, one registry per app so tests can create many apps."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.requests = Histogram(
            "taintwall_request_seconds",
            "HTTP request latency",
            ["endpoint", "status"],
            registry=self.registry,
            buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
        )
        self.tool_calls = Counter(
            "taintwall_tool_call_total", "tool-call decisions", ["decision"], registry=self.registry
        )
        self.tool_outputs = Counter(
            "taintwall_tool_output_total", "tool-output verdicts", ["action"], registry=self.registry
        )
        self.cache = Counter(
            "taintwall_detector_cache_total", "detector cache lookups", ["result"], registry=self.registry
        )
