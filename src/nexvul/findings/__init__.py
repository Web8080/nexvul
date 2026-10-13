"""Finding model and scan result (architecture §12). See :mod:`nexvul.findings.model`."""

from nexvul.findings.model import (
    REPORT_SCHEMA_VERSION,
    Confidence,
    Evidence,
    Finding,
    FindingLocation,
    FlowRole,
    FlowStep,
    Severity,
    Suppression,
    SuppressionStatus,
)

__all__ = [
    "REPORT_SCHEMA_VERSION",
    "Confidence",
    "Evidence",
    "Finding",
    "FindingLocation",
    "FlowRole",
    "FlowStep",
    "Severity",
    "Suppression",
    "SuppressionStatus",
]
