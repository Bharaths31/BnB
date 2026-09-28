from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime

class URLInfo(BaseModel):
    raw_url: str
    normalized: str
    domain: str
    tld: str
    is_punycode: bool
    display_text_mismatch: bool

class AttachmentInfo(BaseModel):
    filename: str
    content_type: str
    size: int
    has_macros: bool

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

class Verdict(BaseModel):
    uid: int
    score: float
    level: str  # ALLOW, FLAG, BLOCK
    reasons: List[str] = Field(default_factory=list)
    component_scores: Dict[str, float] = Field(default_factory=dict)
    explanation: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class AuditEntry(BaseModel):
    uid: int
    action: str
    reason: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
