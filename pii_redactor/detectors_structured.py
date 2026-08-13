"""Structured PII detectors for regex-based patterns."""

from __future__ import annotations
import re
from .detector_base import Detection, PIIDetector
from .config import (
    CAT_EMAIL, CAT_PHONE, CAT_IP, CAT_CC, CAT_SSN,
    CAT_CIN, CAT_PAN, CAT_DIN, CAT_PINCODE,
    CONFIDENCE_HIGH, CONFIDENCE_MEDIUM,
)


def _make_detections(text: str, pattern: re.Pattern, category: str,
                     confidence: float, detector_name: str,
                     validator=None) -> list[Detection]:
    results = []
    for m in pattern.finditer(text):
        value = m.group(0)
        if validator and not validator(value):
            continue
        ctx_start = max(0, m.start() - 40)
        ctx_end   = min(len(text), m.end() + 40)
        results.append(Detection(
            start=m.start(),
            end=m.end(),
            category=category,
            value=value,
            confidence=confidence,
            detector=detector_name,
            context=text[ctx_start:ctx_end],
        ))
    return results


class EmailDetector(PIIDetector):
    """Email detector using RFC 5321 regex."""

    name = "EmailDetector"

    _PATTERN = re.compile(
        r"(?<![a-zA-Z0-9])([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)*\.[a-zA-Z]{2,})",
        re.IGNORECASE,
    )

    def detect(self, text: str) -> list[Detection]:
        return _make_detections(text, self._PATTERN, CAT_EMAIL,
                                CONFIDENCE_HIGH, self.name)



# Phone Detector – Indian numbers (+91 prefix or 10-digit mobile)

class PhoneDetector(PIIDetector):
    """Detects Indian phone numbers."""
    name = "PhoneDetector"

    _PATTERN = re.compile(
        r"""
        (?:
            # +91 followed by 10 digits with optional separators
            \+\s*91[\s\-]*(?:\d[\s\-]*){9}\d
            |
            # 10-digit Indian mobile (starts 6-9)
            \b[6-9]\d{9}\b
        )
        """,
        re.VERBOSE,
    )

    def detect(self, text: str) -> list[Detection]:
        return _make_detections(text, self._PATTERN, CAT_PHONE,
                                CONFIDENCE_HIGH, self.name)



# IP Address Detector

class IPAddressDetector(PIIDetector):
    """IPv4 addresses with octet validation."""
    name = "IPAddressDetector"

    _PATTERN = re.compile(
        r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b"
    )

    @staticmethod
    def _valid_ip(value: str) -> bool:
        parts = value.split(".")
        return all(0 <= int(p) <= 255 for p in parts)

    def detect(self, text: str) -> list[Detection]:
        return _make_detections(text, self._PATTERN, CAT_IP,
                                CONFIDENCE_HIGH, self.name,
                                validator=self._valid_ip)



# Credit Card Detector

class CreditCardDetector(PIIDetector):
    """Luhn-validated 13-19 digit card numbers with optional separators."""
    name = "CreditCardDetector"

    _PATTERN = re.compile(
        r"\b(?:\d{4}[\s\-]?){3}\d{4}(?:[\s\-]?\d{1,3})?\b"
    )

    @staticmethod
    def _luhn(value: str) -> bool:
        digits = [int(c) for c in re.sub(r"\D", "", value)]
        if len(digits) < 13 or len(digits) > 19:
            return False
        total = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0

    def detect(self, text: str) -> list[Detection]:
        return _make_detections(text, self._PATTERN, CAT_CC,
                                CONFIDENCE_HIGH, self.name,
                                validator=self._luhn)



# SSN Detector (US: XXX-XX-XXXX)

class SSNDetector(PIIDetector):
    """US Social Security Numbers – strict format."""
    name = "SSNDetector"

    _PATTERN = re.compile(
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
    )

    def detect(self, text: str) -> list[Detection]:
        return _make_detections(text, self._PATTERN, CAT_SSN,
                                CONFIDENCE_HIGH, self.name)



# CIN Detector (Indian Corporate Identity Number)

class CINDetector(PIIDetector):
    """Detects Indian Corporate Identity Numbers (CIN)."""
    name = "CINDetector"

    _PATTERN = re.compile(
        r"\b[LU]\d{5}[A-Z]{2}\d{4}(?:PLC|LLC|OPC|NPL|PTC|GAP)\d{6}\b"
    )

    def detect(self, text: str) -> list[Detection]:
        return _make_detections(text, self._PATTERN, CAT_CIN,
                                CONFIDENCE_HIGH, self.name)



# PAN Detector (Indian Permanent Account Number)

class PANDetector(PIIDetector):
    """PAN: 5 uppercase alpha + 4 digits + 1 uppercase alpha."""
    name = "PANDetector"

    _PATTERN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")

    # Known false-positive all-caps sequences to exclude
    _EXCLUDE = {"OFFER", "INDIA", "SEBIA", "TOTAL", "ISSUE", "FRESH",
                "SHARE", "PRICE", "RANGE", "FLOOR", "ABOVE", "BELOW",
                "OTHER", "TERMS", "RISKS", "LEGAL", "FINAN"}

    def detect(self, text: str) -> list[Detection]:
        results = []
        for m in self._PATTERN.finditer(text):
            val = m.group(0)
            if val[:5] in self._EXCLUDE:
                continue
            ctx_start = max(0, m.start() - 40)
            ctx_end   = min(len(text), m.end() + 40)
            # extra context check: PAN is usually near "PAN" label
            ctx = text[ctx_start:ctx_end].upper()
            confidence = CONFIDENCE_HIGH if "PAN" in ctx else CONFIDENCE_MEDIUM
            results.append(Detection(
                start=m.start(), end=m.end(),
                category=CAT_PAN, value=val,
                confidence=confidence,
                detector=self.name,
                context=text[ctx_start:ctx_end],
            ))
        return results



# DIN Detector (Director Identification Number – 8 digits)

class DINDetector(PIIDetector):
    """DIN appears near 'DIN' label, 8 consecutive digits."""
    name = "DINDetector"

    _PATTERN = re.compile(
        r"\bDIN\b[:\s]*(\d{8})\b", re.IGNORECASE
    )

    def detect(self, text: str) -> list[Detection]:
        results = []
        for m in self._PATTERN.finditer(text):
            val = m.group(1)
            start = m.start(1)
            end   = m.end(1)
            ctx_start = max(0, m.start() - 20)
            ctx_end   = min(len(text), end + 20)
            results.append(Detection(
                start=start, end=end,
                category=CAT_DIN, value=val,
                confidence=CONFIDENCE_HIGH,
                detector=self.name,
                context=text[ctx_start:ctx_end],
            ))
        return results



# Pincode Detector (Indian 6-digit postal code)

class PincodeDetector(PIIDetector):
    """Detects 6-digit Indian postal codes."""
    name = "PincodeDetector"

    _PATTERN = re.compile(r"\b([1-9]\d{5})\b")

    # Location context keywords
    _LOCATION_KEYWORDS = re.compile(
        r"\b(?:pin(?:\s*code)?|postal|address|road|street|nagar|marg|colony|"
        r"village|taluka|district|city|town|state|india|maharashtra|pune|"
        r"mumbai|delhi|bangalore|chennai|hyderabad|gujarat|rajasthan|"
        r"karnataka|ap|mp|up|bihar|odisha)\b",
        re.IGNORECASE
    )

    def detect(self, text: str) -> list[Detection]:
        results = []
        for m in self._PATTERN.finditer(text):
            val = m.group(1)
            ctx_start = max(0, m.start() - 100)
            ctx_end   = min(len(text), m.end() + 100)
            ctx = text[ctx_start:ctx_end]
            if self._LOCATION_KEYWORDS.search(ctx):
                results.append(Detection(
                    start=m.start(), end=m.end(),
                    category=CAT_PINCODE, value=val,
                    confidence=CONFIDENCE_HIGH,
                    detector=self.name,
                    context=ctx,
                ))
        return results



# Expose all structured detectors in one list

ALL_STRUCTURED_DETECTORS: list[PIIDetector] = [
    EmailDetector(),
    PhoneDetector(),
    IPAddressDetector(),
    CreditCardDetector(),
    SSNDetector(),
    CINDetector(),
    PANDetector(),
    DINDetector(),
    PincodeDetector(),
]
