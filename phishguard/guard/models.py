from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone

from guard.evidence.models import Evidence


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class URLInfo(BaseModel):
    raw_url: str
    normalized: str
    domain: str
    tld: str
    is_punycode: bool
    display_text_mismatch: bool
    #: The visible anchor text associated with this URL (used by cross-modal consistency).
    display_text: str = ""
    #: URL scheme, extracted as a convenience for feature code.
    scheme: str = ""


class AttachmentInfo(BaseModel):
    filename: str
    content_type: str
    size: int
    has_macros: bool
    #: Magic-byte (sniffed) type once the attachment module has inspected the bytes.
    magic_sniffed_type: str = ""
    #: True when extension / declared MIME / magic bytes disagree.
    extension_mismatch: bool = False
    mime_magic_mismatch: bool = False


class ParsedEmail(BaseModel):
    subject: str = ""
    from_addr: str = ""
    from_display: str = ""
    reply_to: str = ""
    return_path: str = ""
    received_chain: List[str] = Field(default_factory=list)
    spf_result: str = "none"
    dkim_result: str = "none"
    dmarc_result: str = "none"
    body_plain: str = ""
    body_html: str = ""
    visible_text: str = ""
    urls: List[URLInfo] = Field(default_factory=list)
    attachments: List[AttachmentInfo] = Field(default_factory=list)
    extracted_image_text: str = ""
    extracted_qr_urls: List[str] = Field(default_factory=list)
    normalized_body: str = ""
    raw_headers: Dict[str, Any] = Field(default_factory=dict)

    # --- Phase 0 extensions (additive, default to empty for backwards compatibility) ---
    #: Envelope recipients (To). Needed by the behavioral profiler.
    recipients: List[str] = Field(default_factory=list)
    #: Carbon-copy recipients.
    cc: List[str] = Field(default_factory=list)
    #: Message timestamp parsed from the Date header.
    received_at: Optional[datetime] = None
    #: Raw attachment bytes for static analysis. Excluded from serialisation and released
    #: once the attachment component has run. Size-capped by the parser.
    attachment_payloads: List[bytes] = Field(default_factory=list, exclude=True)

    # ------------------------------------------------------------------ helpers
    @property
    def sender_domain(self) -> str:
        return self.from_addr.split("@")[-1].lower().strip("<> ") if "@" in self.from_addr else ""

    @property
    def replyto_domain(self) -> str:
        return self.reply_to.split("@")[-1].lower().strip("<> ") if "@" in self.reply_to else ""

    @property
    def return_path_domain(self) -> str:
        return (
            self.return_path.split("@")[-1].lower().strip("<> ")
            if "@" in self.return_path
            else ""
        )

    @property
    def all_recipients(self) -> List[str]:
        return list(dict.fromkeys([*self.recipients, *self.cc]))


class Verdict(BaseModel):
    uid: int
    mailbox: str = ""
    score: float
    #: ALLOW | FLAG | REVIEW | BLOCK
    level: str = "ALLOW"
    reasons: List[str] = Field(default_factory=list)
    component_scores: Dict[str, float] = Field(default_factory=dict)
    explanation: Optional[str] = None
    timestamp: datetime = Field(default_factory=_utcnow)

    # --- Phase 3 extensions (uncertainty / calibration) ---
    calibrated_probability: float = 0.0
    uncertainty: float = 0.0
    confidence: float = 0.0
    #: Ordered evidence objects preserved from every detector (WS11).
    evidence: List[Evidence] = Field(default_factory=list)
    #: Whether any component ran in degraded (fallback) mode.
    degraded: bool = False
    #: Per-component latency in milliseconds (rule 8).
    latencies: Dict[str, float] = Field(default_factory=dict)
    #: Total analysis latency in milliseconds for this email.
    total_latency_ms: float = 0.0
    #: Agreement / disagreement across components (WS7).
    component_agreement: float = 0.0
    component_disagreement: float = 0.0


class AuditEntry(BaseModel):
    uid: int
    action: str
    reason: str
    timestamp: datetime = Field(default_factory=_utcnow)
