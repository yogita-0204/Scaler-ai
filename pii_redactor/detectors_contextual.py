"""Contextual detectors for names, companies, addresses, and DOBs."""

from __future__ import annotations
import re
from .detector_base import Detection, PIIDetector
from .config import (
    CAT_PERSON, CAT_COMPANY, CAT_ADDRESS, CAT_DOB,
    CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW,
    KNOWN_PERSONS, KNOWN_COMPANIES,
)


class PersonNameDetector(PIIDetector):
    """Detects person names using context labels, titles, and known entities."""
    name = "PersonNameDetector"

    # Name component – one or more capitalized words
    _NAME_PART = r"[A-Z][a-zA-Z\-']{1,25}"

    # Titled name: Mr./Mrs./Ms./Dr. <Name> [<Name>]*
    _TITLED = re.compile(
        r"\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Shri|Smt\.?|Prof\.?)\s+"
        r"(" + _NAME_PART + r"(?:\s+" + _NAME_PART + r"){0,3})\b",
    )

    # Context labels that precede a person name
    _CONTEXT_LABELS = re.compile(
        r"(?:Contact\s+Person|Compliance\s+Officer|Company\s+Secretary|"
        r"Managing\s+Director|Executive\s+Director|Whole[- ]Time\s+Director|"
        r"Independent\s+Director|Non[- ]Executive\s+Director|"
        r"Chief\s+(?:Financial\s+)?Officer|Designated\s+Individual|"
        r"Authorised\s+Signatory|Grievance\s+Officer|"
        r"(?:Lead\s+)?Manager|Registrar)[:\s]+",
        re.IGNORECASE,
    )

    # All-caps promoter name (2-4 all-caps words, each 2-20 chars)
    _ALLCAPS_NAME = re.compile(
        r"\b([A-Z]{2,20}(?:\s+[A-Z]{2,20}){1,3})\b"
    )

    # Stop-words that prevent an ALL-CAPS token from being a name
    _ALLCAPS_STOP = {
        "THE", "AND", "FOR", "NOT", "ARE", "WAS", "HAS", "HAD",
        "ITS", "OUR", "THIS", "THAT", "FROM", "WITH", "HAVE",
        "BEEN", "WILL", "ALSO", "SUCH", "EACH", "ONLY", "INTO",
        "UPON", "OVER", "AFTER", "UNDER", "ABOUT", "WHICH", "THEIR",
        "THESE", "THOSE", "BEING", "BOTH", "WITHIN", "BETWEEN",
        "THROUGH", "WITHOUT", "AGAINST", "WHERE", "WHEN",
        # Legal/financial stopwords
        "LIMITED", "PRIVATE", "PUBLIC", "TRUST", "FUND", "BANK",
        "SECURITIES", "CAPITAL", "FINANCIAL", "MANAGEMENT",
        "INTERNATIONAL", "NATIONAL", "INDIA", "SEBI", "BSE", "NSE",
        "EQUITY", "SHARE", "OFFER", "ISSUE", "IPO", "BOOK",
        "BUILT", "FRESH", "SALE", "TOTAL", "PRICE", "FLOOR",
        "RANGE", "QIB", "NII", "RII", "HNI", "ASBA", "UPI",
        "NEFT", "RTGS", "IMPS", "IFSC", "GST", "PAN", "DIN",
        "KYC", "AML", "CFT", "RBI", "MCA", "ROC", "NCLT",
        "ICDR", "LODR", "FEMA", "PMLA", "SARFAESI",
        "PROMOTER", "SELLING", "SHAREHOLDER", "DIRECTOR",
        "CHAIRMAN", "EXECUTIVE", "OFFICER", "SECRETARY",
        "COMPLIANCE", "FINANCE", "OPERATION", "LEGAL",
        "CORPORATE", "REGISTERED", "OFFICE", "CONTACT",
        "EMAIL", "TELEPHONE", "WEBSITE", "FAX",
        "PROSPECTUS", "HERRING", "RED", "DATED",
        "RESERVATION", "AMONG", "WEIGHTED", "AVERAGE", "COST",
        "FACE", "VALUE", "MILLION", "BILLION", "AMOUNT", "SIZE",
        "TYPE", "NAME", "DETAIL", "DATE", "YEAR", "PAGE",
        "SECTION", "CLAUSE", "SCHEDULE", "ANNEXURE", "APPENDIX",
        "FRESH", "ISSUE", "SALE", "AGGREGATE", "EACH", "PER",
        "GENERAL", "RISKS", "GLOBAL", "GROWTH", "MARKET",
        "BUSINESS", "COMPANY", "GROUP", "PARK", "INDUSTRIAL",
        "VENTURE", "SERVICE", "SOLUTION", "PRODUCT", "SYSTEM",
        "RISK", "RETURN", "ASSET", "LIABILITY", "PROFIT", "LOSS",
        # Legal prose phrases that are not names
        "ABSOLUTE", "RESPONSIBILITY", "DECLARATION", "UNDERTAKING",
        "STATEMENT", "ACCOUNTABILITY", "DISCLAIMER",
    }

    # Company suffixes that indicate all-caps is a company not a person
    _COMPANY_SUFFIX = re.compile(
        r"\b(?:LIMITED|LLP|LTD|PVT|PRIVATE|BANK|TRUST|FUND|SECURITIES|"
        r"INDUSTRIAL|PARK|FAMILY|VENTURES|SOLUTIONS|TECHNOLOGIES|SERVICES|"
        r"ENTERPRISES|CORPORATION|HOLDINGS|GROUP|PARTNERS|CAPITAL)\b",
        re.IGNORECASE,
    )

    def detect(self, text: str) -> list[Detection]:
        results: list[Detection] = []
        seen_spans: set[tuple[int,int]] = set()

        def add(start: int, end: int, value: str, conf: float):
            span = (start, end)
            if span not in seen_spans:
                seen_spans.add(span)
                ctx_s = max(0, start - 60)
                ctx_e = min(len(text), end + 60)
                results.append(Detection(
                    start=start, end=end,
                    category=CAT_PERSON, value=value,
                    confidence=conf, detector=self.name,
                    context=text[ctx_s:ctx_e],
                ))

        # 1. Known persons – scan for exact occurrences
        for person in KNOWN_PERSONS:
            # Match flexible whitespace directly so offsets remain valid.
            person_pattern = re.compile(
                r"(?<!\w)" + r"\s+".join(map(re.escape, person.split()))
                + r"(?!\w)",
                re.IGNORECASE,
            )
            for m in person_pattern.finditer(text):
                add(m.start(), m.end(), m.group(0), CONFIDENCE_HIGH)

        # 2. Titled names
        for m in self._TITLED.finditer(text):
            add(m.start(), m.end(), m.group(0), CONFIDENCE_HIGH)

        # 3. Context-label names: "Contact Person: Sarthak Malvadkar"
        # Words that are NOT person names but commonly appear after these labels.
        # Any such word terminates the captured name span.
        _NOT_A_NAME_WORD = {
            "Email", "E", "Telephone", "Tel", "Website", "Www", "Sebi",
            "Registration", "Contact", "Number", "The", "And", "For",
            "An", "In", "Of", "To", "A", "Is", "It", "No", "Not",
            "Company", "Secretary", "Officer", "Manager", "Director",
            "Compliance", "Executive", "Registrar", "Lead", "Authorised",
            "Designated", "Address", "Phone", "Mobile", "Fax", "Grievance",
        }
        for lm in self._CONTEXT_LABELS.finditer(text):
            # read up to 80 chars after the label
            suffix = text[lm.end(): lm.end() + 100]
            nm = re.match(
                r"\s*([A-Z][a-zA-Z]{1,25}(?:[\s/]+[A-Z][a-zA-Z]{1,25}){0,3})", suffix
            )
            if nm:
                name_val = nm.group(1).strip()
                # Must have at least 2 words
                parts = [p for p in re.split(r'[\s/]+', name_val) if p]
                if len(parts) < 2:
                    continue
                # First word must not be a non-name word
                if parts[0] in _NOT_A_NAME_WORD:
                    continue
                # All parts must look like name components (not all-caps abbreviations)
                if any(p.isupper() and len(p) > 3 for p in parts):
                    continue
                # Truncate the span at the first trailing label word so words
                # like "Website" or "Company" are not consumed by the name.
                cut = len(parts)
                for idx, part in enumerate(parts):
                    if part in _NOT_A_NAME_WORD:
                        cut = idx
                        break
                if cut < 2:
                    continue
                # Rebuild the exact substring ending at parts[cut-1], preserving
                # the original separators from the source text.
                cursor = 0
                end_offset = 0
                for part in parts[:cut]:
                    pos = name_val.find(part, cursor)
                    end_offset = pos + len(part)
                    cursor = pos + len(part)
                truncated = name_val[:end_offset]
                start = lm.end() + nm.start(1)
                end = lm.end() + nm.start(1) + len(truncated)
                add(start, end, truncated, CONFIDENCE_HIGH)

        # 4. Promoter section: all-caps person names
        #    Only within ~500 chars after "PROMOTERS" keyword
        #    Each matched group must NOT contain known stop words
        for pm in re.finditer(r"\bPROMOTERS?[:\s]", text):
            window = text[pm.end(): pm.end() + 600]
            for nm in self._ALLCAPS_NAME.finditer(window):
                tokens = nm.group(1).split()
                # All tokens must be 2+ chars
                if any(len(t) < 2 for t in tokens):
                    continue
                # skip if ANY token is a stop word
                if any(t in self._ALLCAPS_STOP for t in tokens):
                    continue
                # skip if has company suffix
                if self._COMPANY_SUFFIX.search(nm.group(1)):
                    continue
                # Must look like a name: 2-4 proper tokens
                if len(tokens) < 2 or len(tokens) > 4:
                    continue
                start = pm.end() + nm.start()
                end   = pm.end() + nm.end()
                add(start, end, nm.group(1), CONFIDENCE_MEDIUM)

        return results


# ============================================================================
# COMPANY NAME DETECTOR
# ============================================================================

class CompanyNameDetector(PIIDetector):
    """
    Detects company/legal-entity names via:
    1. Known-entity list
    2. Company suffix patterns (Limited, LLP, Pvt. Ltd., etc.)
    3. Trust/Family-trust patterns
    """
    name = "CompanyNameDetector"

    # Suffix pattern: 1-5 capitalized words (no conjunctions) followed by company suffix
    # Each word component: Capital + lowercase letters/digits, allowing & and . (for LLP names)
    _WORD = r"[A-Z][a-zA-Z0-9]{1,25}"
    _SEP  = r"(?:\s+(?:&\s+)?|\s*&\s*)"  # space or & separator between name words
    _SUFFIX = re.compile(
        r"(?<!\w)("
        + _WORD + r"(?:" + _SEP + _WORD + r"){0,4}"
        + r"\s+)"
        r"(Limited|Pvt\.?\s*Ltd\.?|Private\s+Limited|LLP|"
        r"Incorporated|Inc\.|Corp\.|Corporation|"
        r"Bank(?:\s+Limited)?|Securities(?:\s+Limited)?|"
        r"(?:Asset\s+)?Management(?:\s+(?:Company|Limited))?|"
        r"Chartered\s+Accountants?|Advocates?\s+(?:&\s+Solicitors?)?)"
    )

    _TRUST = re.compile(
        r"(?<!\w)([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){0,3}\s+(?:Family\s+)?Trust)\b",
    )


    def detect(self, text: str) -> list[Detection]:
        results: list[Detection] = []
        seen: set[tuple[int,int]] = set()

        def add(start, end, value, conf):
            span = (start, end)
            if span not in seen:
                seen.add(span)
                ctx_s = max(0, start - 60)
                ctx_e = min(len(text), end + 60)
                results.append(Detection(
                    start=start, end=end,
                    category=CAT_COMPANY, value=value,
                    confidence=conf, detector=self.name,
                    context=text[ctx_s:ctx_e],
                ))

        # Adjective prefixes that indicate a generic phrase, not a company name
        _GENERIC_PREFIXES = {
            "Senior", "Key", "Top", "Middle", "Junior", "General",
            "Executive", "Group", "Risk", "Market", "Asset", "Fund",
            "Our", "Their", "This", "Whole", "Full", "Core", "Basic",
            "Day", "Year", "Month",
        }

        # 1. Known companies
        for company in KNOWN_COMPANIES:
            for m in re.finditer(re.escape(company), text, re.IGNORECASE):
                add(m.start(), m.end(), m.group(0), CONFIDENCE_HIGH)

        # 2. Suffix-based
        for m in self._SUFFIX.finditer(text):
            val = m.group(0).strip()
            if len(val) <= 8:  # skip very short false matches
                continue
            # Skip generic phrases
            first_word = val.split()[0] if val.split() else ""
            if first_word in _GENERIC_PREFIXES:
                continue
            # "Private Limited" or "Limited" alone is not a company name
            if val.lower() in {"private limited", "limited", "llp", "ltd."}:
                continue
            add(m.start(), m.end(), val, CONFIDENCE_MEDIUM)

        # 3. Trust names
        for m in self._TRUST.finditer(text):
            val = m.group(0).strip()
            first_word = val.split()[0] if val.split() else ""
            if first_word in _GENERIC_PREFIXES:
                continue
            add(m.start(), m.end(), val, CONFIDENCE_MEDIUM)

        return results


# ============================================================================
# ADDRESS DETECTOR
# ============================================================================

class AddressDetector(PIIDetector):
    """
    Detects physical/mailing addresses.
    Focuses on the DOCX prospectus patterns:
    - Building/plot numbers followed by location names
    - Contains state/city/country context
    """
    name = "AddressDetector"

    # Starts with a building/plot number
    _ADDR_START = re.compile(
        r"\b(\d+(?:[/,]\s*\d+)*(?:\s+and\s+\d+(?:[/,]\s*\d+)*)?(?:[,\s]+(?:Village|Bldg\.?|Plot(?:\s+No\.?)?|"
        r"Door(?:\s+No\.?)?|House(?:\s+No\.?)?|Floor|Wing|Tower|Sector|Block|"
        r"Phase|Survey\s+No\.?|Plot\s+No\.?))?[,\s]+"
        r"[A-Z][a-zA-Z\s,\.\-]{10,200}"
        r"(?:Village|Taluka|District|Maharashtra|Pune|Mumbai|Delhi|Bangalore|Hyderabad|Chennai|India)"
        r"[^\n]{0,80})",
        re.IGNORECASE,
    )

    # Specific registered/corporate office pattern
    _OFFICE_ADDR = re.compile(
        r"(?:Registered\s+Office|Corporate\s+Office|Regd\.?\s+Office|"
        r"Principal\s+Place\s+of\s+Business)[:\s]+"
        r"([^•\n]{20,300}(?:India|Maharashtra|Mumbai|Pune|[1-9]\d{5}))",
        re.IGNORECASE,
    )

    _ADDRESS_MARKER = re.compile(
        r"\b(?:village|road|street|nagar|marg|colony|tower|building|bldg|"
        r"plot|floor|wing|sector|block|phase|survey|taluka|district|"
        r"lane|complex|industrial\s+park|registered\s+office|corporate\s+office)\b",
        re.IGNORECASE,
    )

    def detect(self, text: str) -> list[Detection]:
        results: list[Detection] = []
        seen: set[tuple[int,int]] = set()

        def add(start, end, value, conf):
            span = (start, end)
            if (
                span not in seen
                and len(value.strip()) > 15
                and (conf >= CONFIDENCE_HIGH or self._ADDRESS_MARKER.search(value))
            ):
                seen.add(span)
                ctx_s = max(0, start - 40)
                ctx_e = min(len(text), end + 40)
                results.append(Detection(
                    start=start, end=end,
                    category=CAT_ADDRESS, value=value.strip(),
                    confidence=conf, detector=self.name,
                    context=text[ctx_s:ctx_e],
                ))

        for m in self._ADDR_START.finditer(text):
            add(m.start(), m.end(), m.group(1), CONFIDENCE_MEDIUM)

        for m in self._OFFICE_ADDR.finditer(text):
            add(m.start(1), m.end(1), m.group(1), CONFIDENCE_HIGH)

        return results


# ============================================================================
# DATE OF BIRTH DETECTOR
# ============================================================================

class DOBDetector(PIIDetector):
    """
    Detects dates that appear in a DOB/birth context.
    Avoids flagging all dates – only those near DOB keywords.
    """
    name = "DOBDetector"

    _DATE_PATTERN = re.compile(
        r"""
        \b(?:
            \d{1,2}[\s/\-\.]\d{1,2}[\s/\-\.]\d{2,4}               # DD/MM/YYYY
            |
            \d{1,2}\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|
                         Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|
                         Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|
                         Nov(?:ember)?|Dec(?:ember)?)\s+\d{2,4}     # D Month YYYY
            |
            (?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|
               Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|
               Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|
               Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+\d{2,4}  # Month D, YYYY
        )\b
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    _DOB_CONTEXT = re.compile(
        r"\b(?:date\s+of\s+birth|dob|born\s+on|d\.o\.b\.?|birthday)\b",
        re.IGNORECASE,
    )

    def detect(self, text: str) -> list[Detection]:
        results: list[Detection] = []
        # Find all DOB context positions
        dob_positions = [m.start() for m in self._DOB_CONTEXT.finditer(text)]

        for m in self._DATE_PATTERN.finditer(text):
            # Check if date is within 100 chars of a DOB keyword
            near_dob = any(abs(m.start() - pos) < 100 for pos in dob_positions)
            if near_dob:
                ctx_s = max(0, m.start() - 50)
                ctx_e = min(len(text), m.end() + 50)
                results.append(Detection(
                    start=m.start(), end=m.end(),
                    category=CAT_DOB, value=m.group(0),
                    confidence=CONFIDENCE_HIGH,
                    detector=self.name,
                    context=text[ctx_s:ctx_e],
                ))
        return results


# ============================================================================
# All contextual detectors
# ============================================================================
ALL_CONTEXTUAL_DETECTORS: list[PIIDetector] = [
    PersonNameDetector(),
    CompanyNameDetector(),
    AddressDetector(),
    DOBDetector(),
]
