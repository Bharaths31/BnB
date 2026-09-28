"""Safe static attachment analysis (WS5)."""
from guard.attachment.analyzer import (
    AttachmentAnalysisResult,
    AttachmentComponent,
    AttachmentResult,
    analyze_attachment,
)
from guard.attachment.magic import detect, extension_mismatch, mime_magic_mismatch

__all__ = [
    "AttachmentComponent",
    "AttachmentAnalysisResult",
    "AttachmentResult",
    "analyze_attachment",
    "detect",
    "extension_mismatch",
    "mime_magic_mismatch",
]
