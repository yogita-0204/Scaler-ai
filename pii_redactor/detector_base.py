"""Base detection types and overlap resolution."""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Detection:
    """Represents a single detected PII span in a flat text string."""
    start: int            # character offset in the flat string
    end: int              # exclusive character offset
    category: str         # PII category constant
    value: str            # original raw text
    confidence: float     # 0.0 – 1.0
    detector: str         # name of the detector that produced this
    replacement: Optional[str] = None   # filled in later by pseudonymiser
    context: str = ""     # surrounding text for audit

    def __len__(self) -> int:
        return self.end - self.start

    def overlaps(self, other: "Detection") -> bool:
        return self.start < other.end and other.start < self.end


class PIIDetector:
    """Abstract base class for all detectors."""
    name: str = "base"

    def detect(self, text: str) -> list[Detection]:
        raise NotImplementedError


def resolve_overlaps(detections: list[Detection]) -> list[Detection]:
    """
    Resolve overlapping detections by assigning every character position to
    the single best detection covering it. The best detection at a position is
    the one with the highest confidence; ties are broken by longer span, then
    by earlier start. Contiguous positions sharing the same winner are merged
    into one clipped Detection span.

    This maximizes redaction coverage: a high-confidence short span no longer
    suppresses longer spans outside its own region (chained-overlap safety).
    """
    if not detections:
        return []

    def rank(d: Detection) -> tuple[float, int, int]:
        # Higher confidence first, then longer span, then earlier start.
        return (-d.confidence, -(d.end - d.start), d.start)

    # Sweep-line over span boundaries.
    events: list[tuple[int, int, Detection]] = []  # (position, is_start, det)
    for det in detections:
        events.append((det.start, 1, det))
        events.append((det.end, 0, det))
    events.sort(key=lambda e: (e[0], -e[1]))

    active: list[Detection] = []
    result: list[Detection] = []
    cursor: int | None = None
    winner: Detection | None = None

    index = 0
    while index < len(events):
        position = events[index][0]
        # Process every boundary at this position together.
        starts: list[Detection] = []
        ends: list[Detection] = []
        while index < len(events) and events[index][0] == position:
            _, is_start, det = events[index]
            if is_start:
                starts.append(det)
            else:
                ends.append(det)
            index += 1
        for det in ends:
            active.remove(det)
        for det in starts:
            active.append(det)

        new_winner = min(active, key=rank) if active else None
        if new_winner is not winner:
            if winner is not None and cursor is not None and position > cursor:
                result.append(_clip(winner, cursor, position))
            winner = new_winner
            cursor = position

    return result


def _clip(detection: Detection, start: int, end: int) -> Detection:
    """Return a copy of `detection` restricted to the [start, end) span."""
    return Detection(
        start=start,
        end=end,
        category=detection.category,
        value=detection.value,
        confidence=detection.confidence,
        detector=detection.detector,
        replacement=detection.replacement,
        context=detection.context,
    )
