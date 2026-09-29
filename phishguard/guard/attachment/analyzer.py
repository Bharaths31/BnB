"""Static attachment analyzer + component (WS5).

Never executes an attachment. Every attachment is sniffed by magic bytes, then inspected
according to its real type (archive / Office / PDF / SVG-HTML-text / image). Generic features
such as "contains a macro" are surfaced to fusion and never block on their own.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from guard.attachment.archive import ArchiveFindings, ArchiveLimits, inspect_archive
from guard.attachment.features import (
    aggregate,
    extract_urls,
    file_entropy,
    filename_risk,
    script_indicator,
    sha256,
)
from guard.attachment.magic import (
    DOCX,
    HTML,
    ICS,
    OLE,
    PDF,
    PPTX,
    SVG,
    TXT,
    XLSX,
    ZIP,
    detect,
    extension_mismatch,
    mime_magic_mismatch,
)
from guard.attachment.office import analyze_office
from guard.attachment.pdf import analyze_pdf
from guard.component import AnalysisContext, ComponentResult
from guard.config import policy
from guard.evidence import Evidence, EvidenceCategory

MODULE = "attachment"


class AttachmentResult(BaseModel):
    filename: str = ""
    content_type: str = ""
    magic_type: str = ""
    size: int = 0
    risk_score: float = 0.0
    features: Dict[str, float] = Field(default_factory=dict)


class AttachmentAnalysisResult(BaseModel):
    risk_score: float = 0.0
    per_attachment: List[AttachmentResult] = Field(default_factory=list)
    aggregate_features: Dict[str, float] = Field(default_factory=dict)
    evidence: List[str] = Field(default_factory=list)


def _limits() -> ArchiveLimits:
    cfg = policy.get("attachment", {})
    return ArchiveLimits(
        max_depth=int(cfg.get("max_depth", 3)),
        max_files=int(cfg.get("max_files_per_archive", 500)),
        max_total_bytes=int(cfg.get("max_total_uncompressed_bytes", 100 * 1024 * 1024)),
        max_compression_ratio=int(cfg.get("max_compression_ratio", 100)),
    )


def _max_attachment_bytes() -> int:
    return int(policy.get("attachment", {}).get("max_attachment_bytes", 10 * 1024 * 1024))


def analyze_attachment(
    filename: str,
    content_type: str,
    payload: bytes,
    limits: Optional[ArchiveLimits] = None,
    ctx: Optional[AnalysisContext] = None,
) -> AttachmentResult:
    limits = limits or _limits()
    if payload is None:
        payload = b""
    elif isinstance(payload, str):
        payload = payload.encode("utf-8", "replace")
    elif not isinstance(payload, (bytes, bytearray)):
        payload = bytes(payload)
    payload = bytes(payload)
    magic_type = detect(payload)
    ext_mismatch = extension_mismatch(filename, magic_type)
    mime_mismatch = mime_magic_mismatch(content_type, magic_type)

    features: Dict[str, float] = {
        "filename_risk": filename_risk(filename),
        "extension_mismatch": 1.0 if ext_mismatch else 0.0,
        "mime_magic_mismatch": 1.0 if mime_mismatch else 0.0,
        "file_entropy": file_entropy(payload),
        "archive_depth": 0.0,
        "nested_archive_count": 0.0,
        "embedded_url_count": 0.0,
        "embedded_domain_count": 0.0,
        "macro_indicator": 0.0,
        "external_relationship_count": 0.0,
        "script_indicator": 0.0,
        "suspicious_pdf_action": 0.0,
        "suspicious_office_relationship": 0.0,
        "attachment_size_anomaly": min(1.0, len(payload) / max(1, _max_attachment_bytes())),
        "attachment_hash_reputation": _hash_reputation(payload, ctx),
    }

    bomb = False
    truncated = False
    if magic_type == PDF:
        pdf = analyze_pdf(payload)
        features["embedded_url_count"] = float(len(pdf.embedded_urls))
        features["embedded_domain_count"] = float(len(pdf.embedded_domains))
        features["suspicious_pdf_action"] = 1.0 if pdf.suspicious_action else 0.0
    elif magic_type in (DOCX, XLSX, PPTX, OLE):
        office = analyze_office(payload, magic_type)
        features["macro_indicator"] = 1.0 if office.macro_indicator else 0.0
        features["external_relationship_count"] = float(office.external_relationship_count)
        features["embedded_url_count"] = float(len(office.embedded_urls))
        features["embedded_domain_count"] = float(len(office.embedded_domains))
        features["suspicious_office_relationship"] = (
            1.0 if office.external_relationship_count or office.remote_template else 0.0
        )
        findings = inspect_archive(payload, limits)
        _apply_archive(features, findings)
        bomb = findings.bomb_suspected
        truncated = findings.truncated
    elif magic_type in (ZIP,):
        findings = inspect_archive(payload, limits)
        _apply_archive(features, findings)
        features["embedded_url_count"] = float(max(features["embedded_url_count"], len(findings.embedded_urls)))
        features["embedded_domain_count"] = float(max(features["embedded_domain_count"], len(findings.embedded_domains)))
        bomb = findings.bomb_suspected
        truncated = findings.truncated
    elif magic_type in (SVG, HTML, TXT, ICS):
        features["script_indicator"] = 1.0 if script_indicator(payload) else 0.0
        urls = extract_urls(payload)
        features["embedded_url_count"] = float(len(urls))

    risk = _risk_score(features, bomb, truncated)
    return AttachmentResult(
        filename=filename or "unknown",
        content_type=content_type or "",
        magic_type=magic_type,
        size=len(payload),
        risk_score=round(risk, 4),
        features=features,
    )


def _apply_archive(features: Dict[str, float], findings: ArchiveFindings) -> None:
    features["archive_depth"] = float(findings.max_depth)
    features["nested_archive_count"] = float(findings.nested_archive_count)
    if findings.macro_indicator:
        features["macro_indicator"] = 1.0
    if findings.dangerous_members:
        features["script_indicator"] = max(features["script_indicator"], 0.5)


def _hash_reputation(payload: bytes, ctx: Optional[AnalysisContext]) -> float:
    if not payload or ctx is None:
        return 0.0
    bad = set(ctx.extra.get("bad_hashes") or [])
    return 1.0 if bad and sha256(payload) in bad else 0.0


def _risk_score(features: Dict[str, float], bomb: bool, truncated: bool = False) -> float:
    score = 0.0
    if features["attachment_hash_reputation"]:
        score = max(score, 1.0)
    if bomb:
        score = max(score, 0.7)
    if truncated:
        score = max(score, 0.4)
    if features["extension_mismatch"]:
        score = max(score, 0.7)
    if features["filename_risk"] >= 0.8:
        score = max(score, 0.55)
    if features["macro_indicator"]:
        score = max(score, 0.6)
    if features["script_indicator"]:
        score = max(score, 0.6)
    if features["suspicious_pdf_action"]:
        score = max(score, 0.55)
    if features["suspicious_office_relationship"]:
        score = max(score, 0.5)
    if features["mime_magic_mismatch"]:
        score = max(score, 0.45)
    if features["nested_archive_count"] > 0:
        score = max(score, 0.4)
    if features["embedded_url_count"] > 0:
        score = max(score, 0.3)
    return min(1.0, score)


class AttachmentComponent:
    name = "attachment"

    def run(self, parsed, ctx: AnalysisContext) -> ComponentResult:
        attachments = list(getattr(parsed, "attachments", []) or [])
        payloads = list(getattr(parsed, "attachment_payloads", []) or [])
        if not attachments:
            return ComponentResult(name=self.name, features={"attachment_count": 0.0})

        limits = _limits()
        results: List[AttachmentResult] = []
        for index, att in enumerate(attachments):
            payload = payloads[index] if index < len(payloads) else b""
            results.append(analyze_attachment(att.filename, att.content_type, payload, limits, ctx))

        agg = aggregate([r.features for r in results])
        evidence: List[Evidence] = []
        for result in results:
            if result.risk_score >= 0.5:
                evidence.append(
                    Evidence.of(EvidenceCategory.ATTACHMENT, "attachment_risk",
                                f"{result.filename} ({result.magic_type})", result.risk_score, MODULE,
                                related_entity=result.filename)
                )
            for name in ("macro_indicator", "extension_mismatch", "suspicious_pdf_action", "script_indicator"):
                if result.features.get(name):
                    evidence.append(
                        Evidence.of(EvidenceCategory.ATTACHMENT, name,
                                    f"{result.filename}", result.features[name] or 0.6, MODULE,
                                    related_entity=result.filename)
                    )

        return ComponentResult(name=self.name, features=agg, evidence=evidence)

    def fallback(self, parsed, ctx: AnalysisContext) -> ComponentResult:
        return ComponentResult(name=self.name, features={"attachment_count": 0.0}, degraded=True)


__all__ = [
    "AttachmentComponent",
    "AttachmentAnalysisResult",
    "AttachmentResult",
    "analyze_attachment",
]
