"""
Evaluation Module
==================
Builds a gold-standard test set, runs detectors against it,
and computes TP/FP/FN/TN, Precision, Recall, Accuracy, F1
per category and overall.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from .detector_base import Detection
from .detectors_structured import ALL_STRUCTURED_DETECTORS
from .detectors_contextual import ALL_CONTEXTUAL_DETECTORS
from .config import (
    CAT_EMAIL, CAT_PHONE, CAT_IP, CAT_CC, CAT_SSN,
    CAT_DOB, CAT_ADDRESS, CAT_PERSON, CAT_COMPANY,
    CAT_CIN, CAT_PAN, CAT_DIN, CAT_PINCODE,
    REDACT_THRESHOLD,
)


@dataclass
class GoldExample:
    text: str
    pii_type: str          # expected category
    expected: bool         # True = IS PII, False = NOT PII
    description: str = ""  # human-readable label


@dataclass
class CategoryMetrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.fn + self.tn
        return (self.tp + self.tn) / total if total > 0 else 0.0


# ---------------------------------------------------------------------------
# Gold-standard examples – real and synthetic, positive and negative
# ---------------------------------------------------------------------------
GOLD_SET: list[GoldExample] = [
    # ---- EMAIL ----
    GoldExample("Email: cs.connect@kshinternational.com is the contact",
                CAT_EMAIL, True, "Real doc email"),
    GoldExample("Send to ipo@trilegal.com for queries",
                CAT_EMAIL, True, "Real doc legal email"),
    GoldExample("My address is 45 Park Avenue",
                CAT_EMAIL, False, "No email present"),
    GoldExample("Order number is 12345 not an email",
                CAT_EMAIL, False, "Number, not email"),
    GoldExample("The ratio is 2/3 which is fine",
                CAT_EMAIL, False, "Fraction, not email"),
    GoldExample("john.doe@example.com wrote back",
                CAT_EMAIL, True, "Synthetic email"),
    GoldExample("test@test.c is malformed",
                CAT_EMAIL, False, "Malformed TLD"),

    # ---- PHONE ----
    GoldExample("Telephone: +91 20 45053237",
                CAT_PHONE, True, "Real doc phone"),
    GoldExample("Call +91 22 4009 4400 for support",
                CAT_PHONE, True, "Real doc phone with spaces"),
    GoldExample("+91 81081 14949 is the number",
                CAT_PHONE, True, "Real doc mobile"),
    GoldExample("The invoice is for ₹4,200.00 million",
                CAT_PHONE, False, "Financial figure, not phone"),
    GoldExample("Section 32 of the Companies Act",
                CAT_PHONE, False, "Section number, not phone"),
    GoldExample("9876543210 is a valid mobile",
                CAT_PHONE, True, "10-digit mobile"),
    GoldExample("12345 is a short number",
                CAT_PHONE, False, "Too short for phone"),

    # ---- IP ADDRESS ----
    GoldExample("Server at 192.168.1.1 is down",
                CAT_IP, True, "Private IP"),
    GoldExample("Public IP: 203.0.113.42",
                CAT_IP, True, "Public IP"),
    GoldExample("Version 3.14.159 is latest",
                CAT_IP, False, "Version number, not IP (would pass Luhn check differently)"),
    GoldExample("256.1.2.3 is invalid",
                CAT_IP, False, "Invalid octet"),

    # ---- CREDIT CARD ----
    GoldExample("Card: 4532015112830366",
                CAT_CC, True, "Valid Luhn Visa number"),
    GoldExample("Card: 1234567890123456",
                CAT_CC, False, "Fails Luhn check"),
    GoldExample("Revenue of 4532015112830366 million",
                CAT_CC, False, "Financial context – Luhn may pass but this is ambiguous"),

    # ---- SSN ----
    GoldExample("SSN: 123-45-6789",
                CAT_SSN, True, "Standard SSN format"),
    GoldExample("000-45-6789 is invalid",
                CAT_SSN, False, "Invalid SSN (000 area)"),
    GoldExample("Reference 123-45-6789 in the report",
                CAT_SSN, True, "SSN in context"),

    # ---- CIN ----
    GoldExample("CIN: U28129PN1979PLC141032",
                CAT_CIN, True, "Real doc CIN"),
    GoldExample("CIN: U67190MH1999PTC118368",
                CAT_CIN, True, "Real doc CIN #2"),
    GoldExample("The section is U/s 32 of the Act",
                CAT_CIN, False, "Not a CIN"),

    # ---- PAN ----
    GoldExample("PAN: AABCK1234D is registered",
                CAT_PAN, True, "Synthetic PAN near label"),
    GoldExample("TOTAL shares offered",
                 CAT_PAN, False, "All-caps word, not PAN"),

    # ---- DIN ----
    GoldExample("Director DIN: 01234567",
                 CAT_DIN, True, "Director identification number"),
    GoldExample("Reference number 12345678",
                 CAT_DIN, False, "Unlabelled number, not DIN"),

    # ---- PINCODE ----
    GoldExample("Registered address: Pune 410501, Maharashtra",
                 CAT_PINCODE, True, "Indian postal code in address"),
    GoldExample("Offer size: 410501 shares",
                 CAT_PINCODE, False, "Standalone number, not pincode"),

    # ---- DOB ----
    GoldExample("Date of birth: 15/08/1985",
                CAT_DOB, True, "DOB with label"),
    GoldExample("DOB: January 10, 1990",
                CAT_DOB, True, "DOB with label, long format"),
    GoldExample("The offer closes on December 10, 2025",
                CAT_DOB, False, "Offer date, not DOB"),
    GoldExample("Dated December 10, 2025",
                CAT_DOB, False, "Document date, not DOB"),

    # ---- PERSON ----
    GoldExample("Contact Person: Sarthak Malvadkar Company Secretary",
                CAT_PERSON, True, "Real doc contact person"),
    GoldExample("KUSHAL SUBBAYYA HEGDE is a promoter",
                CAT_PERSON, True, "Promoter name"),
    GoldExample("The offer is for QIBs and RIIs",
                CAT_PERSON, False, "Abbreviations, not names"),

    # ---- COMPANY ----
    GoldExample("Lead Manager: Nuvama Wealth Management Limited",
                CAT_COMPANY, True, "Real doc company"),
    GoldExample("Registered with HDFC Bank Limited",
                CAT_COMPANY, True, "Bank name"),
    GoldExample("under the Companies Act 2013",
                CAT_COMPANY, False, "Act reference, not a specific company"),

    # ---- ADDRESS ----
    GoldExample(
        "Registered Office: 11/3, 11/4 and 11/5 Village Birdewadi "
        "Chakan Taluka - Khed, Pune – 410 501, Maharashtra, India",
        CAT_ADDRESS, True, "Real doc registered office"),
    GoldExample("See page 398 for details",
                CAT_ADDRESS, False, "Page reference, not address"),
]


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

def _detect_category(text: str, category: str) -> bool:
    """Run all detectors on text; return True if `category` is detected."""
    all_dets: list[Detection] = []
    for det in ALL_STRUCTURED_DETECTORS + ALL_CONTEXTUAL_DETECTORS:
        try:
            all_dets.extend(det.detect(text))
        except Exception:
            pass
    found_cats = {d.category for d in all_dets if d.confidence >= REDACT_THRESHOLD}
    return category in found_cats


def run_evaluation() -> dict[str, CategoryMetrics]:
    """
    Run the gold set through detectors and compute per-category metrics.
    Returns dict[category_name, CategoryMetrics].
    """
    metrics: dict[str, CategoryMetrics] = {}

    for ex in GOLD_SET:
        cat = ex.pii_type
        if cat not in metrics:
            metrics[cat] = CategoryMetrics()

        detected = _detect_category(ex.text, cat)

        if ex.expected and detected:
            metrics[cat].tp += 1
        elif ex.expected and not detected:
            metrics[cat].fn += 1
        elif not ex.expected and detected:
            metrics[cat].fp += 1
        else:
            metrics[cat].tn += 1

    return metrics


def compute_overall(metrics: dict[str, CategoryMetrics]) -> CategoryMetrics:
    overall = CategoryMetrics()
    for m in metrics.values():
        overall.tp += m.tp
        overall.fp += m.fp
        overall.fn += m.fn
        overall.tn += m.tn
    return overall


def format_report(metrics: dict[str, CategoryMetrics],
                  doc_detections: list[Detection] | None = None) -> str:
    """Format evaluation metrics as a clean Markdown table."""
    overall = compute_overall(metrics)
    lines = []
    lines.append("## Validation Benchmark")
    lines.append("")
    lines.append("| Category | Precision | Recall | F1 Score | Accuracy | TP | FP | FN | TN |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for cat, m in sorted(metrics.items()):
        lines.append(
            f"| {cat} | {m.precision:.1%} | {m.recall:.1%} | {m.f1:.3f} | "
            f"{m.accuracy:.1%} | {m.tp} | {m.fp} | {m.fn} | {m.tn} |"
        )
    lines.append(
        f"| **OVERALL** | **{overall.precision:.1%}** | **{overall.recall:.1%}** | "
        f"**{overall.f1:.3f}** | **{overall.accuracy:.1%}** | "
        f"**{overall.tp}** | **{overall.fp}** | **{overall.fn}** | **{overall.tn}** |"
    )
    lines.append("")

    if doc_detections:
        from collections import Counter
        cat_counts = Counter(d.category for d in doc_detections)
        lines.append("## Document Detections Summary")
        lines.append("")
        lines.append(f"Total detections in document: **{len(doc_detections)}**")
        lines.append("")
        lines.append("| Category | Count |")
        lines.append("|---|---|")
        for cat, count in sorted(cat_counts.items()):
            lines.append(f"| {cat} | {count} |")
        lines.append("")

    return "\n".join(lines)
