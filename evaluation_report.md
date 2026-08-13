# Evaluation Report

**Processing time:** 0.8 seconds
**Total detections:** 628

## Validation Benchmark

| Category | Precision | Recall | F1 Score | Accuracy | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| ADDRESS | 100.0% | 100.0% | 1.000 | 100.0% | 1 | 0 | 0 | 1 |
| CIN | 100.0% | 100.0% | 1.000 | 100.0% | 2 | 0 | 0 | 1 |
| COMPANY_NAME | 100.0% | 100.0% | 1.000 | 100.0% | 2 | 0 | 0 | 1 |
| CREDIT_CARD | 50.0% | 100.0% | 0.667 | 66.7% | 1 | 1 | 0 | 1 |
| DATE_OF_BIRTH | 100.0% | 100.0% | 1.000 | 100.0% | 2 | 0 | 0 | 2 |
| DIN | 100.0% | 100.0% | 1.000 | 100.0% | 1 | 0 | 0 | 1 |
| EMAIL | 100.0% | 100.0% | 1.000 | 100.0% | 3 | 0 | 0 | 4 |
| IP_ADDRESS | 100.0% | 100.0% | 1.000 | 100.0% | 2 | 0 | 0 | 2 |
| PAN | 100.0% | 100.0% | 1.000 | 100.0% | 1 | 0 | 0 | 1 |
| PERSON_NAME | 100.0% | 100.0% | 1.000 | 100.0% | 2 | 0 | 0 | 1 |
| PHONE | 100.0% | 100.0% | 1.000 | 100.0% | 4 | 0 | 0 | 3 |
| PINCODE | 100.0% | 100.0% | 1.000 | 100.0% | 1 | 0 | 0 | 1 |
| SSN | 100.0% | 100.0% | 1.000 | 100.0% | 2 | 0 | 0 | 1 |
| **OVERALL** | **96.0%** | **100.0%** | **0.980** | **97.8%** | **24** | **1** | **0** | **20** |

## Document Detections Summary

Total detections in document: **628**

| Category | Count |
|---|---|
| ADDRESS | 27 |
| CIN | 9 |
| COMPANY_NAME | 304 |
| EMAIL | 104 |
| PERSON_NAME | 142 |
| PHONE | 33 |
| PINCODE | 9 |


## Leakage Scan Results

- Original PII values checked: **192**
- Original values literally still present: **0**
- Residual detector matches after redaction: **0**
- Document clean: **True**

## Approach Summary

### Detection Pipeline

1. **Structured detectors**: Pattern matching with validation checks for emails, phone numbers, IP addresses, credit cards (Luhn validated), SSNs, CINs, PANs, DINs, and Pincodes.
2. **Contextual detectors**: Rule-based matching for person names, company names, addresses, and DOBs based on contextual keywords and entity lists.
3. **Deterministic pseudonymisation**: Maps each unique original value to a consistent fake replacement using MD5-seeded hashing.
4. **Overlap resolution**: Resolves overlapping detections using confidence scoring and span length.

### Implementation Notes & Limitations

- **Dates**: Only dates with DOB context are redacted to prevent redacting valid financial dates in the prospectus.
- **Names & Companies**: Unlisted names or companies in plain prose without contextual markers may not be caught by regex rules alone.
- **Images**: Scans text in XML nodes (body, tables, headers, footers). Raster image text requires OCR.