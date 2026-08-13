"""
Post-Redaction Leakage Scanner
================================
Scans the OUTPUT DOCX for remaining original PII that should have been redacted.
Returns a report of any detected leakage.
"""

from __future__ import annotations
from pathlib import Path

from .docx_processor import detect_all, extract_docx_paragraphs, extract_docx_text
from .detector_base import Detection


def scan_for_leakage(output_docx_path: str,
                     original_detections: list[Detection]) -> dict:
    """
    Checks whether any ORIGINAL PII values are still literally present
    in the output DOCX text.

    Strategy: search for original values and independently run the detectors
    over output text. Generated replacements are excluded only from the
    independent detector results, never from literal original-value checks.

    Returns:
        {
          "literal_leaks": list[dict],  # genuine originals still in output
          "checked_originals": int,
          "remaining_pii": list[dict],
          "clean": bool,
        }
    """
    path = Path(output_docx_path)
    if not path.exists():
        return {"error": f"Output file not found: {output_docx_path}"}

    # Generated values are expected detector matches, not residual originals.
    all_replacements_lower = {
        (det.replacement or "").lower().strip()
        for det in original_detections
    }

    # Extract all text from output DOCX
    output_text = extract_docx_text(output_docx_path)
    output_lower = output_text.lower()

    # Check each original detection value
    literal_leaks = []
    seen_values: set[str] = set()

    for det in original_detections:
        val = det.value.strip()
        val_lower = val.lower()
        if val_lower in seen_values:
            continue
        seen_values.add(val_lower)

        # Check if original value still appears literally in output
        if val_lower in output_lower:
            literal_leaks.append({
                "category": det.category,
                "value": val,
                "replacement": det.replacement,
            })

    remaining_pii = []
    seen_remaining: set[tuple[str, str]] = set()
    for paragraph in extract_docx_paragraphs(output_docx_path):
        for detection in detect_all(paragraph):
            key = (detection.category, detection.value.lower().strip())
            if key in seen_remaining or any(
                replacement and replacement in key[1]
                for replacement in all_replacements_lower
            ):
                continue
            seen_remaining.add(key)
            remaining_pii.append({
                "category": detection.category,
                "value": detection.value,
            })

    return {
        "literal_leaks": literal_leaks,
        "checked_originals": len(seen_values),
        "remaining_pii": remaining_pii,
        "clean": not literal_leaks and not remaining_pii,
    }
