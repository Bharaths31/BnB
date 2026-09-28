# guard/explainer/templates.py

EXPLANATION_TEMPLATES = {
    "urgency": {
        "header": "This email attempts to create a false sense of urgency.",
        "detail": "It uses phrases associated with urgency (e.g., 'immediate', 'urgent action') to pressure you into acting without thinking."
    },
    "authority": {
        "header": "This email impersonates an authority figure.",
        "detail": "The sender is pretending to be a CEO, manager, or official entity to demand compliance."
    },
    "credential_request": {
        "header": "This email asks for your login credentials.",
        "detail": "Legitimate services rarely ask you to log in directly from an email link to 'verify' your identity."
    },
    "financial": {
        "header": "This email is soliciting a financial transaction.",
        "detail": "It involves a request for a wire transfer, invoice payment, or gift cards."
    },
    "general": {
        "header": "This email exhibits common phishing characteristics.",
        "detail": "Our models have detected patterns in the text often used by malicious actors."
    },
    "url_mismatch": {
        "header": "Suspicious Links Detected.",
        "detail": "The email contains links where the visible text does not match the actual destination."
    },
    "headers_anomaly": {
        "header": "Sender Address Anomalies.",
        "detail": "The 'Reply-To' or 'Return-Path' addresses do not match the visible 'From' address, suggesting spoofing."
    }
}
