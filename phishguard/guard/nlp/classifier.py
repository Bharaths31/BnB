import numpy as np
from optimum.onnxruntime import ORTModelForSequenceClassification
from transformers import AutoTokenizer
import os
import structlog

logger = structlog.get_logger()

class PhishingClassifier:
    def __init__(self):
        self.model_path = "/app/data/processed/text_classifier_onnx"
        self.ready = False
        try:
            if os.path.exists(self.model_path):
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
                self.model = ORTModelForSequenceClassification.from_pretrained(self.model_path)
                self.ready = True
                logger.info("ONNX Text Classifier loaded")
            else:
                logger.warning(f"ONNX model not found at {self.model_path}, using dummy mode")
        except Exception as e:
            logger.error("Failed to load ONNX model", error=str(e))
        
    def classify(self, text: str) -> float:
        if not self.ready:
            # Dummy fallback if model isn't downloaded yet
            if "update your account" in text.lower():
                return 0.85
            elif "urgent wire" in text.lower():
                return 0.90
            elif "verify your identity" in text.lower():
                return 0.88
            return 0.1
            
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        outputs = self.model(**inputs)
        logits = outputs.logits.detach().cpu().numpy()[0]
        
        # Softmax to get probability
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / exp_logits.sum()
        
        # The model 'cybersectony/phishing-email-detection-distilbert_v2.1' 
        # usually has label 1 as 'Phishing' and label 0 as 'Safe'. 
        # Let's extract the probability of the positive class (index 1).
        return float(probs[1]) if len(probs) > 1 else float(probs[0])

classifier = PhishingClassifier()
