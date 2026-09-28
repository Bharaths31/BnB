import mailparser
from guard.models import ParsedEmail, URLInfo, AttachmentInfo
from guard.parse.normalizer import normalize_text, normalize_url
from guard.parse.html_sanitizer import sanitize_html
from guard.parse.ocr import extract_text_from_image, extract_qr_urls
from bs4 import BeautifulSoup
import re

def parse_email(raw_bytes: bytes) -> ParsedEmail:
    mail = mailparser.parse_from_bytes(raw_bytes)
    parsed = ParsedEmail()
    
    parsed.subject = mail.subject or ""
    if mail.from_:
        parsed.from_display, parsed.from_addr = mail.from_[0]
        
    parsed.raw_headers = mail.headers
    
    if "Reply-To" in mail.headers:
        parsed.reply_to = mail.headers["Reply-To"]
    if "Return-Path" in mail.headers:
        parsed.return_path = mail.headers["Return-Path"]
        
    parsed.body_plain = " ".join(mail.text_plain)
    parsed.body_html = " ".join(mail.text_html)
    
    if parsed.body_html:
        parsed.visible_text = sanitize_html(parsed.body_html)
    else:
        parsed.visible_text = parsed.body_plain
        
    parsed.normalized_body = normalize_text(parsed.visible_text)
    
    urls = []
    if parsed.body_html:
        soup = BeautifulSoup(parsed.body_html, 'html.parser')
        for a in soup.find_all('a', href=True):
            href = a['href']
            text = a.get_text()
            norm_url = normalize_url(href)
            domain = ""
            if "://" in norm_url:
                domain = norm_url.split("://")[1].split("/")[0]
                
            urls.append(URLInfo(
                raw_url=href,
                normalized=norm_url,
                domain=domain,
                tld=domain.split('.')[-1] if '.' in domain else "",
                is_punycode="xn--" in domain,
                display_text_mismatch=text.strip() != "" and "://" in text and domain not in text
            ))
            
    parsed.urls = urls
    
    attachments = []
    for att in mail.attachments:
        payload = att.get('payload', b"")
        filename = att.get('filename', 'unknown')
        content_type = att.get('mail_content_type', '')
        
        has_macros = filename.endswith(('.docm', '.xlsm'))
        attachments.append(AttachmentInfo(
            filename=filename,
            content_type=content_type,
            size=len(payload),
            has_macros=has_macros
        ))
        
        if content_type.startswith('image/'):
            parsed.extracted_image_text += extract_text_from_image(payload) + " "
            parsed.extracted_qr_urls.extend(extract_qr_urls(payload))
            
    parsed.attachments = attachments
    return parsed
