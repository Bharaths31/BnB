"""Static attachment analysis tests (WS5) — the 10 required scenarios."""
import io
import zipfile

from guard.attachment import AttachmentComponent, analyze_attachment
from guard.attachment.archive import ArchiveLimits
from guard.component import AnalysisContext
from guard.models import AttachmentInfo
from tests.factories import make_email

LEGIT_PDF = b"%PDF-1.4\n1 0 obj<<>>\nstream\nhello\nendstream\n%%EOF"
PHISH_PDF = (
    b"%PDF-1.4\n/OpenAction << /S /JavaScript /JS (app.alert(1)) >>\n"
    b"/URI (http://evil.example.net/login)\n/Launch\n%%EOF"
)


def _zip(members, compression=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _macro_doc():
    return _zip({
        "[Content_Types].xml": b"<Types/>",
        "word/document.xml": b"<w:document>hello</w:document>",
        "word/vbaProject.bin": b"\xd0\xcf\x11\xe0 macro",
    })


def _plain_xlsx():
    return _zip({
        "[Content_Types].xml": b"<Types/>",
        "xl/workbook.xml": b"<workbook/>",
        "xl/worksheets/sheet1.xml": b"<sheet>1</sheet>",
    })


def test_legitimate_pdf():
    result = analyze_attachment("report.pdf", "application/pdf", LEGIT_PDF)
    assert result.magic_type == "pdf"
    assert result.risk_score == 0.0
    assert result.features["suspicious_pdf_action"] == 0.0


def test_phishing_pdf():
    result = analyze_attachment("invoice.pdf", "application/pdf", PHISH_PDF)
    assert result.features["suspicious_pdf_action"] == 1.0
    assert result.features["embedded_url_count"] >= 1
    assert result.risk_score >= 0.5


def test_macro_document():
    result = analyze_attachment("invoice.docm", "application/vnd.ms-word.document.macroEnabled.12", _macro_doc())
    assert result.magic_type == "docx"
    assert result.features["macro_indicator"] == 1.0
    assert result.risk_score >= 0.6


def test_ordinary_spreadsheet():
    result = analyze_attachment("budget.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", _plain_xlsx())
    assert result.magic_type == "xlsx"
    assert result.features["macro_indicator"] == 0.0
    assert result.risk_score == 0.0


def test_nested_zip():
    inner = _zip({"note.txt": b"hello"})
    outer = _zip({"inner.zip": inner, "readme.txt": b"top level"})
    result = analyze_attachment("bundle.zip", "application/zip", outer)
    assert result.features["nested_archive_count"] >= 1
    assert result.features["archive_depth"] >= 2


def test_extension_spoofing():
    # A .pdf that is actually a ZIP — extension disagrees with magic bytes.
    payload = _zip({"x.txt": b"hidden"})
    result = analyze_attachment("invoice.pdf", "application/pdf", payload)
    assert result.magic_type == "zip"
    assert result.features["extension_mismatch"] == 1.0
    assert result.risk_score >= 0.7


def test_svg_with_external_reference():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    result = analyze_attachment("logo.svg", "image/svg+xml", svg)
    assert result.magic_type == "svg"
    assert result.features["script_indicator"] == 1.0
    assert result.risk_score >= 0.6


def test_malformed_attachment_does_not_crash():
    result = analyze_attachment("weird.bin", "application/octet-stream", b"\x00\x01\x02\xff\xfe\x00garbage")
    assert result.risk_score == 0.0
    assert result.magic_type in ("unknown", "txt")


def test_oversized_archive_is_bounded():
    members = {f"file{i}.txt": b"data" * 10 for i in range(10)}
    payload = _zip(members)
    result = analyze_attachment("big.zip", "application/zip", payload, limits=ArchiveLimits(max_files=3))
    # Inspection is truncated (we cannot fully vet it) but must not blow up.
    assert result.features["archive_depth"] >= 1
    assert result.risk_score >= 0.4


def test_decompression_bomb_protection():
    # 4 MB of zeros compresses to a tiny member -> extreme ratio.
    payload = _zip({"bomb.bin": b"\x00" * (4 * 1024 * 1024)})
    result = analyze_attachment("bomb.zip", "application/zip", payload)
    assert result.risk_score >= 0.7  # flagged, without attempting full decompression


def test_component_aggregates_and_emits_evidence():
    parsed = make_email(
        from_addr="billing@vendor.test",
        attachments=[
            ("invoice.docm", "application/vnd.ms-word.document.macroEnabled.12", _macro_doc()),
            ("report.pdf", "application/pdf", LEGIT_PDF),
        ],
    )
    result = AttachmentComponent().run(parsed, AnalysisContext())
    assert result.features["attachment_count"] == 2.0
    assert result.features["macro_indicator"] == 1.0
    assert any(e.category.value == "ATTACHMENT" for e in result.evidence)
