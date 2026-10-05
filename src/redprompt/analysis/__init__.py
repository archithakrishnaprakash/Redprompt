"""Response analysis: detection-result container and layered detectors.

The detector implementations land in Phase 4; this package defines the shared
:class:`DetectionResult` contract used by tests, evidence, and reporting.
"""

from __future__ import annotations

from redprompt.analysis.base import DetectionResult, combine

__all__ = ["DetectionResult", "combine"]
