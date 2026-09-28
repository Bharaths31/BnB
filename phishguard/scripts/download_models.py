import os
import structlog
from transformers import AutoTokenizer

try:
    from optimum.onnxruntime import ORTModelForSequenceClassification
except ImportError:
    import subprocess
    import sys
    print("optimum[onnxruntime] not installed. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "optimum[onnxruntime]"])
    from optimum.onnxruntime import ORTModelForSequenceClassification

logger = structlog.get_logger()

def download_and_export_models():
    base_dir = "/app/data/processed"
    os.makedirs(base_dir, exist_ok=True)
    
    # 1. Text Phishing Classifier (DistilBERT)
    model_id = "cybersectony/phishing-email-detection-distilbert_v2.1"
    output_dir = os.path.join(base_dir, "text_classifier_onnx")
    
    if not os.path.exists(output_dir):
        logger.info(f"Downloading and exporting {model_id} to ONNX...")
        try:
            # Load PyTorch model and export to ONNX automatically
            model = ORTModelForSequenceClassification.from_pretrained(model_id, export=True)
            tokenizer = AutoTokenizer.from_pretrained(model_id)
            
            # Save the exported ONNX model and tokenizer
            model.save_pretrained(output_dir)
            tokenizer.save_pretrained(output_dir)
            logger.info("Successfully exported Text Classifier to ONNX.")
        except Exception as e:
            logger.error(f"Failed to export {model_id}: {e}")
    else:
        logger.info(f"Model already exists at {output_dir}")

    # (Future) 2. SecureBERT Embeddings
    # (Future) 3. Tactic Multi-Label Classifier
    
if __name__ == "__main__":
    download_and_export_models()
