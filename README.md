# PII Redaction Tool

This project automatically detects and redacts Personally Identifiable Information (PII) from `.docx` files, specifically tuned for the 127-page Red Herring Prospectus. It replaces all detected sensitive fields with realistic fake values while keeping formatting, tables, headers, and footers intact.

---

## Features

- **Supported PII Types**: Redacts Person Names, Company Names, Addresses, Email Addresses, Phone Numbers, SSNs, Credit Card Numbers, Dates of Birth, IP Addresses, and Indian identifiers (CIN, PAN, DIN, Pincodes).
- **Consistent Pseudonymisation**: Uses seeded hashing so that the same person or company always gets the same fake replacement throughout the document.
- **DOCX XML Preserving**: Modifies text nodes at the WordprocessingML level without breaking paragraph styles, run formatting, or table cells.
- **Leakage Scanning**: Includes a post-processing check to verify that no original PII strings remain in the output document.
- **Evaluation Benchmark**: Measures precision, recall, F1-score, and accuracy across categories on a validation set.

---

## Setup & Installation

Requires Python 3.10+.

```bash
# Clone the repository
git clone https://github.com/yogita-0204/Scaler-ai.git
cd Scaler-ai

# Install dependencies
python3 -m pip install -r requirements.txt
```

---

## How to Run

### Run Full Redaction Pipeline

Redact the prospectus and write the report:

```bash
python3 -m pii_redactor \
  --input "Red Herring Prospectus.docx" \
  --output "redacted_prospectus.docx" \
  --report-path "evaluation_report.md"
```

### Run Tests

Run the test suite:

```bash
python3 -m pytest tests/ -v
```

### Evaluation Only

Run detector evaluation on the validation set:

```bash
python3 -m pii_redactor --evaluate-only
```

### Leakage Scan Only

Scan an existing output DOCX against input detections:

```bash
python3 -m pii_redactor \
  --scan-only \
  --input "Red Herring Prospectus.docx" \
  --output "redacted_prospectus.docx"
```

---

## How It Works

1. **Extraction**: Reads text across body paragraphs, tables, headers, footers, and field codes using `python-docx` and `lxml`.
2. **Detection**: Runs regex matchers (email, phone, CIN, PAN, etc.) and contextual/heuristic rules (person names, company names, addresses, DOBs).
3. **Overlap Resolution**: If two rules detect overlapping text, the higher-confidence match is selected.
4. **Replacement**: Generates consistent fake replacements (e.g. `alice.gupta@placeholder.co.in`) seeded by the original value.
5. **XML Editing**: Replaces text inside OpenXML text elements directly to keep surrounding document formatting untouched.

---

## Project Structure

```
├── pii_redactor/
│   ├── __init__.py
│   ├── __main__.py             # CLI entry point & report generation
│   ├── config.py               # Constants, thresholds, entity lists
│   ├── detector_base.py        # Base detection class & overlap resolution
│   ├── detectors_structured.py # Regex detectors (email, phone, IP, CIN, etc.)
│   ├── detectors_contextual.py # Rule detectors (names, companies, address, DOB)
│   ├── docx_processor.py       # DOCX OpenXML reader/writer
│   ├── evaluator.py            # Gold-set precision/recall evaluator
│   ├── leakage_scanner.py      # Post-redaction leakage checker
│   └── pseudonymiser.py        # Deterministic fake data generator
├── tests/                      # Unit and integration tests
├── evaluation_report.md        # Pipeline output & evaluation results
├── README.md
├── requirements.txt
└── LICENSE                     # MIT License
```

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
