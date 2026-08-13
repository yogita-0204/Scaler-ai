"""CLI runner for PII redaction."""

from __future__ import annotations
import argparse
import time
from pathlib import Path

from .config import INPUT_DOCX, OUTPUT_DOCX
from .docx_processor import DocxProcessor
from .evaluator import run_evaluation, format_report
from .leakage_scanner import scan_for_leakage


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="PII Redaction Tool")
    parser.add_argument("--input", default=INPUT_DOCX,
                        help="Path to input DOCX")
    parser.add_argument("--output", default=OUTPUT_DOCX,
                        help="Path to output redacted DOCX")
    parser.add_argument("--evaluate-only", action="store_true",
                        help="Only run gold-set evaluation")
    parser.add_argument("--scan-only", action="store_true",
                        help="Only run leakage scan on existing output")
    parser.add_argument("--report-path", default=None,
                        help="Path to write evaluation report")
    args = parser.parse_args(argv)

    report_path = args.report_path or str(
        Path(args.output).parent / "evaluation_report.md"
    )

    if args.evaluate_only:
        print("Running gold-set evaluation...")
        metrics = run_evaluation()
        report = format_report(metrics)
        print(report)
        with open(report_path, "w") as f:
            f.write("# Evaluation Report\n\n" + report + "\n")
        print(f"\nReport written to: {report_path}")
        return 0

    if args.scan_only:
        print(f"Scanning {args.output} for remaining PII...")
        if not Path(args.input).exists():
            parser.error(f"Input DOCX is required for --scan-only: {args.input}")
        if not Path(args.output).exists():
            parser.error(f"Output DOCX not found: {args.output}")
        original_detections = DocxProcessor.collect_detections(args.input)
        result = scan_for_leakage(args.output, original_detections)
        leaked = result.get("literal_leaks", [])
        print(f"Original PII values checked: {result.get('checked_originals', 0)}")
        print(f"Literal leaks remaining: {len(leaked)}")
        print(f"Clean: {result.get('clean', False)}")
        return 0 if result.get("clean", False) else 1

    print("PII Redaction Tool")
    print(f"Input:  {args.input}")
    print(f"Output: {args.output}")
    print()

    # Step 1: Process the document
    print("[1/4] Processing document...")
    t0 = time.time()
    processor = DocxProcessor(args.input, args.output)
    detections = processor.process()
    t1 = time.time()
    print(f"      Done in {t1-t0:.1f}s – {len(detections)} detections")

    # Step 2: Print detection summary
    from collections import Counter
    cat_counts = Counter(d.category for d in detections)
    print("\n[2/4] Detection summary:")
    for cat, count in sorted(cat_counts.items()):
        print(f"      {cat:<20} {count:>5}")

    # Step 3: Run gold-set evaluation
    print("\n[3/4] Running gold-set evaluation...")
    metrics = run_evaluation()

    # Step 4: Leakage scan
    print("\n[4/4] Running leakage scan...")
    scan_result = scan_for_leakage(args.output, detections)
    literal_leaks = scan_result.get("literal_leaks", [])
    print(f"      Checked original PII values: {scan_result.get('checked_originals', 0)}")
    print(f"      Literal leaks remaining:     {len(literal_leaks)}")
    clean_flag = scan_result.get("clean", False)
    print(f"      Clean: {clean_flag}")

    if not clean_flag:
        print("\n      Leaked values (sample):")
        for leak in literal_leaks[:10]:
            print(f"      [{leak['category']}] {leak['value'][:60]}")

    # Generate report
    report = format_report(metrics, detections)
    full_report = _build_full_report(report, detections, scan_result, t1 - t0)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(full_report)

    print(f"\nEvaluation report: {report_path}")
    print(f"Redacted DOCX:     {args.output}")
    print()
    print(report)
    return 0 if clean_flag else 1


def _build_full_report(eval_report: str, detections, scan_result, elapsed: float) -> str:
    lines = []
    lines.append("# Evaluation Report")
    lines.append("")
    lines.append(f"**Processing time:** {elapsed:.1f} seconds")
    lines.append(f"**Total detections:** {len(detections)}")
    lines.append("")
    lines.append(eval_report)
    lines.append("")

    lines.append("## Leakage Scan Results")
    lines.append("")
    literal_leaks = scan_result.get("literal_leaks", [])
    checked = scan_result.get("checked_originals", 0)
    lines.append(f"- Original PII values checked: **{checked}**")
    lines.append(f"- Original values literally still present: **{len(literal_leaks)}**")
    lines.append(
        f"- Residual detector matches after redaction: **{len(scan_result.get('remaining_pii', []))}**"
    )
    lines.append(f"- Document clean: **{scan_result.get('clean', False)}**")
    lines.append("")

    if literal_leaks:
        lines.append("### Leaked Values (samples)")
        lines.append("")
        for d in literal_leaks[:10]:
            lines.append(f"- `{d['category']}`: `{str(d['value'])[:60]}`")
        lines.append("")

    lines.append("## Approach Summary")
    lines.append("")
    lines.append("""
### Detection Pipeline

1. **Structured detectors**: Pattern matching with validation checks for emails, phone numbers, IP addresses, credit cards (Luhn validated), SSNs, CINs, PANs, DINs, and Pincodes.
2. **Contextual detectors**: Rule-based matching for person names, company names, addresses, and DOBs based on contextual keywords and entity lists.
3. **Deterministic pseudonymisation**: Maps each unique original value to a consistent fake replacement using MD5-seeded hashing.
4. **Overlap resolution**: Resolves overlapping detections using confidence scoring and span length.

### Implementation Notes & Limitations

- **Dates**: Only dates with DOB context are redacted to prevent redacting valid financial dates in the prospectus.
- **Names & Companies**: Unlisted names or companies in plain prose without contextual markers may not be caught by regex rules alone.
- **Images**: Scans text in XML nodes (body, tables, headers, footers). Raster image text requires OCR.
""".strip())
    return "\n".join(lines)



if __name__ == "__main__":
    raise SystemExit(main())
