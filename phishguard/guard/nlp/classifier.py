import os

import numpy as np
import structlog

logger = structlog.get_logger()


class PhishingClassifier:
    """ONNX-backed phishing text classifier with a deterministic fallback.

    The optional heavy dependencies (``optimum`` / ``transformers``) are imported lazily so
    that the module can be imported — and the rest of the pipeline can run — on a CPU-only
    machine with no ONNX artifacts. When the model is unavailable the deterministic keyword
    heuristic is used, exactly as before.
    """

    def __init__(self):
        self.model_path = os.environ.get(
            "PHISHGUARD_TEXT_MODEL_PATH", "/app/data/processed/text_classifier_onnx"
        )
        self.ready = False
        self.tokenizer = None
        self.model = None
        try:  # pragma: no cover - requires optional ONNX runtime
            if os.path.exists(self.model_path):
                from optimum.onnxruntime import ORTModelForSequenceClassification
                from transformers import AutoTokenizer

                self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
                self.model = ORTModelForSequenceClassification.from_pretrained(self.model_path)
                self.ready = True
                logger.info("ONNX Text Classifier loaded")
            else:
                logger.warning("ONNX model not found, using deterministic fallback",
                               path=self.model_path)
        except Exception as e:  # pragma: no cover - optional dependency
            logger.error("Failed to load ONNX model", error=str(e))

    def classify(self, text: str) -> float:
        text = text or ""
        if not self.ready:
            return self._fallback(text)

        try:  # pragma: no cover - requires ONNX runtime
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
            outputs = self.model(**inputs)
            logits = outputs.logits.detach().cpu().numpy()[0]
            exp_logits = np.exp(logits - np.max(logits))
            probs = exp_logits / exp_logits.sum()
            return float(probs[1]) if len(probs) > 1 else float(probs[0])
        except Exception as e:
            logger.error("Text classifier inference failed, using fallback", error=str(e))
            return self._fallback(text)

    @staticmethod
    def _fallback(text: str) -> float:
        lowered = text.lower()
        if "update your account" in lowered:
            return 0.85
        if "urgent wire" in lowered:
            return 0.90
        if "verify your identity" in lowered:
            return 0.88
        return 0.1


classifier = PhishingClassifier()
