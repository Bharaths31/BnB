class TacticClassifier:
    def __init__(self):
        self.ready = True
        self.tactics = ["urgency", "authority", "credential_request", "financial"]

    def classify(self, text: str) -> dict:
        # Dummy
        res = {t: 0.0 for t in self.tactics}
        if "urgent" in text.lower() or "immediately" in text.lower():
            res["urgency"] = 0.9
        if "ceo" in text.lower() or "boss" in text.lower():
            res["authority"] = 0.8
        if "verify" in text.lower() or "login" in text.lower():
            res["credential_request"] = 0.95
        if "wire" in text.lower() or "invoice" in text.lower():
            res["financial"] = 0.85
        return res

tactic_classifier = TacticClassifier()
