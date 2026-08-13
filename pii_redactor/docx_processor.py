"""DOCX-wide PII detection and redaction.

The processor edits WordprocessingML text nodes directly. This keeps run
properties, hyperlinks, tables, headers, footers, and other XML structure
intact instead of rebuilding paragraphs through python-docx runs.
"""

from __future__ import annotations

import os
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from lxml import etree

from .config import REDACT_THRESHOLD
from .detector_base import Detection, resolve_overlaps
from .detectors_contextual import ALL_CONTEXTUAL_DETECTORS
from .detectors_structured import ALL_STRUCTURED_DETECTORS
from .pseudonymiser import get_replacement

WORD_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
XML_NS = "http://www.w3.org/XML/1998/namespace"
NAMESPACES = {"w": WORD_NS}
TEXT_XPATH = ".//w:t | .//w:instrText | .//w:delText"


def detect_all(text: str) -> list[Detection]:
    """Run every detector, filter low-confidence results, and pseudonymise."""
    detections: list[Detection] = []
    for detector in ALL_STRUCTURED_DETECTORS + ALL_CONTEXTUAL_DETECTORS:
        try:
            detections.extend(detector.detect(text))
        except Exception as exc:
            raise RuntimeError(f"{detector.name} failed during detection") from exc

    resolved = resolve_overlaps(
        [d for d in detections if d.confidence >= REDACT_THRESHOLD]
    )
    for detection in resolved:
        detection.replacement = get_replacement(
            detection.category, detection.value
        )
    return resolved


def _text_nodes(paragraph: etree._Element) -> list[etree._Element]:
    nodes = paragraph.xpath(TEXT_XPATH, namespaces=NAMESPACES)
    result = []
    for node in nodes:
        parent = node.getparent()
        nested_paragraph = False
        while parent is not None and parent is not paragraph:
            if parent.tag == f"{{{WORD_NS}}}p":
                nested_paragraph = True
                break
            parent = parent.getparent()
        if not nested_paragraph:
            result.append(node)
    return result


def _paragraph_detections(paragraph: etree._Element) -> list[Detection]:
    text = "".join(node.text or "" for node in _text_nodes(paragraph))
    return detect_all(text) if text.strip() else []


def _node_ranges(nodes: list[etree._Element]) -> list[tuple[int, int]]:
    ranges = []
    cursor = 0
    for node in nodes:
        length = len(node.text or "")
        ranges.append((cursor, cursor + length))
        cursor += length
    return ranges


def _set_text(node: etree._Element, value: str) -> None:
    node.text = value
    if value[:1].isspace() or value[-1:].isspace():
        node.set(f"{{{XML_NS}}}space", "preserve")
    else:
        node.attrib.pop(f"{{{XML_NS}}}space", None)


def _replace_detection(
    nodes: list[etree._Element], detection: Detection
) -> None:
    """Replace one flat-text span while preserving every affected run."""
    ranges = _node_ranges(nodes)
    start_index = next(
        (i for i, (_, end) in enumerate(ranges) if detection.start < end), None
    )
    end_position = max(detection.start, detection.end - 1)
    end_index = next(
        (i for i, (_, end) in enumerate(ranges) if end_position < end), None
    )
    if start_index is None or end_index is None:
        return

    replacement = detection.replacement or f"[REDACTED_{detection.category}]"
    start_begin, _ = ranges[start_index]
    first_text = nodes[start_index].text or ""
    last_text = nodes[end_index].text or ""

    if start_index == end_index:
        local_start = detection.start - start_begin
        local_end = detection.end - start_begin
        _set_text(
            nodes[start_index],
            first_text[:local_start] + replacement + first_text[local_end:],
        )
        return

    first_local_start = detection.start - start_begin
    last_local_end = detection.end - ranges[end_index][0]
    _set_text(nodes[start_index], first_text[:first_local_start] + replacement)
    for index in range(start_index + 1, end_index):
        _set_text(nodes[index], "")
    _set_text(nodes[end_index], last_text[last_local_end:])


def _redact_paragraph(paragraph: etree._Element) -> list[Detection]:
    nodes = _text_nodes(paragraph)
    if not nodes:
        return []
    detections = _paragraph_detections(paragraph)
    for detection in sorted(detections, key=lambda item: item.start, reverse=True):
        _replace_detection(nodes, detection)
    return detections


def _process_xml(xml: bytes) -> tuple[bytes, list[Detection]]:
    root = etree.fromstring(xml)
    detections: list[Detection] = []
    for paragraph in root.xpath(".//w:p", namespaces=NAMESPACES):
        detections.extend(_redact_paragraph(paragraph))
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True), detections


def _iter_word_xml(archive: zipfile.ZipFile):
    for item in archive.infolist():
        if item.filename.startswith("word/") and item.filename.endswith(".xml"):
            yield item


@dataclass
class DocxProcessor:
    input_path: str
    output_path: str
    all_detections: list[Detection] | None = None

    def process(self) -> list[Detection]:
        """Redact every paragraph in every WordprocessingML XML part."""
        detections: list[Detection] = []
        output = Path(self.output_path)
        if Path(self.input_path).resolve() == output.resolve():
            raise ValueError("Input and output paths must be different")
        output.parent.mkdir(parents=True, exist_ok=True)
        temp_fd, temp_name = tempfile.mkstemp(
            prefix=".redacted-", suffix=".docx", dir=output.parent
        )
        os.close(temp_fd)
        temp_path = Path(temp_name)
        try:
            with zipfile.ZipFile(self.input_path, "r") as source, zipfile.ZipFile(
                temp_path, "w", compression=zipfile.ZIP_DEFLATED
            ) as target:
                for item in source.infolist():
                    data = source.read(item.filename)
                    if item.filename.startswith("word/") and item.filename.endswith(".xml"):
                        data, found = _process_xml(data)
                        detections.extend(found)
                    target.writestr(item, data)
            os.replace(temp_path, output)
        finally:
            if temp_path.exists():
                temp_path.unlink()
        self.all_detections = detections
        return detections

    @staticmethod
    def collect_detections(input_path: str) -> list[Detection]:
        """Detect PII in an existing DOCX without modifying it."""
        detections: list[Detection] = []
        with zipfile.ZipFile(input_path, "r") as archive:
            for item in _iter_word_xml(archive):
                try:
                    root = etree.fromstring(archive.read(item.filename))
                except etree.XMLSyntaxError:
                    continue
                for paragraph in root.xpath(".//w:p", namespaces=NAMESPACES):
                    nodes = _text_nodes(paragraph)
                    text = "".join(node.text or "" for node in nodes)
                    if text.strip():
                        detections.extend(detect_all(text))
        return detections


def extract_docx_text(docx_path: str) -> str:
    """Extract paragraph text from all WordprocessingML parts."""
    return "\n".join(extract_docx_paragraphs(docx_path))


def extract_docx_paragraphs(docx_path: str) -> list[str]:
    """Extract each WordprocessingML paragraph independently."""
    parts: list[str] = []
    with zipfile.ZipFile(docx_path, "r") as archive:
        for item in _iter_word_xml(archive):
            try:
                root = etree.fromstring(archive.read(item.filename))
            except etree.XMLSyntaxError:
                continue
            for paragraph in root.xpath(".//w:p", namespaces=NAMESPACES):
                text = "".join(node.text or "" for node in _text_nodes(paragraph))
                if text:
                    parts.append(text)
    return parts
