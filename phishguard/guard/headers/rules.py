from guard.models import ParsedEmail
import numpy as np

def check_authentication(parsed: ParsedEmail) -> dict:
    auth_results = parsed.raw_headers.get("Authentication-Results", "")
    return {
        "spf_fail": "spf=fail" in auth_results.lower(),
        "dkim_fail": "dkim=fail" in auth_results.lower(),
        "dmarc_fail": "dmarc=fail" in auth_results.lower()
    }

def check_header_anomalies(parsed: ParsedEmail) -> dict:
    from_domain = parsed.from_addr.split('@')[-1] if '@' in parsed.from_addr else ""
    return_domain = parsed.return_path.split('@')[-1] if '@' in parsed.return_path else ""
    reply_to_domain = parsed.reply_to.split('@')[-1] if '@' in parsed.reply_to else ""
    
    return {
        "from_return_mismatch": bool(from_domain and return_domain and from_domain != return_domain),
        "from_reply_mismatch": bool(from_domain and reply_to_domain and from_domain != reply_to_domain),
        "display_name_suspicious": parsed.from_display.lower() in ["admin", "support", "billing"] and from_domain not in ["google.com", "microsoft.com", "amazon.com", "paypal.com"]
    }

def get_header_features(parsed: ParsedEmail) -> np.ndarray:
    auth = check_authentication(parsed)
    anom = check_header_anomalies(parsed)
    
    return np.array([
        auth["spf_fail"],
        auth["dkim_fail"],
        auth["dmarc_fail"],
        anom["from_return_mismatch"],
        anom["from_reply_mismatch"],
        anom["display_name_suspicious"]
    ], dtype=np.float32)
